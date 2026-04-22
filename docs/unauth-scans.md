# Unauthenticated AWS recon

Some AWS services leak attacker-useful identifiers through the
client-side bundles of their consuming web apps. The `cse aws unauth`
sub-tree wraps the recon flows for those leaks behind a single CLI:
no AWS credentials are required.

Three commands are currently wired up:

- [`cognito`](#cse-aws-unauth-cognito) — user / identity pool + client id hunt.
- [`s3`](#cse-aws-unauth-s3) — bucket hunt, public-access probes, optional
  wordlist bruteforce + object sampling.
- [`api-gateway`](#cse-aws-unauth-api-gateway) — REST / HTTP / WebSocket
  API Gateway + Lambda Function URL fingerprinting.

All three share the same crawler + credential regex sweep: extraction
regexes differ but the `--url` → crawl → extract pipeline is identical.

## `cse aws unauth cognito`

Crawls a web app, regex-extracts Cognito `userPoolId`, `identityPoolId`
and app `clientId` values from every same-origin HTML / JS / JSON body
it can reach, then optionally fingerprints each pool by talking to the
public Cognito service endpoints.

```bash
cse aws unauth cognito --url https://app.example.com
```

### What it does

1. **Recursive same-origin crawl.** Starts at `--url`, follows
   `<script src>`, `<link href>`, `<a href>`, inline `<script>` URLs,
   webpack chunk manifests, and dynamic-import string literals, until
   no new same-origin URLs remain or `--max-pages` (default 250) is
   hit. Binary content (images, fonts, video) is skipped; text bodies
   over 5 MB are dropped.
2. **Regex extraction.** Every text body is matched against three
   patterns:
   - `userPoolId`     — `<region>_<suffix>` (e.g. `us-east-1_abc123XYZ`)
   - `identityPoolId` — `<region>:<uuid>` (e.g. `us-east-1:11111111-2222-3333-4444-555555555555`)
   - `appClientId`    — anchored on `userPoolWebClientId` / `appClientId`
     / `clientId` / `client_id` keys
3. **Safe Cognito probes** (`--probe`, on by default). For each
   discovered pool, the runner makes one or two unauthenticated calls:
   - `GetId` against every identity pool — checks whether
     unauthenticated identities are issued.
   - `InitiateAuth` against every (user pool, client id) pair — leaks
     which auth flows the pool accepts and validates the client id.
4. **SignUp probe** (`--probe-signup`, opt-in). For each
   (user pool, client id) pair, sends a `SignUp` request with an
   intentionally invalid password (`"a"`). The response is
   classified, never persisted:
   - `InvalidPasswordException` / `InvalidParameterException` →
     self-registration is enabled (the pool got far enough to
     complain about the password).
   - `NotAuthorizedException: SignUp is not permitted` →
     self-registration is disabled.
5. **Secret regex sweep.** Every crawled body is also fed through
   `cloud_service_enum.core.secrets.scan_text`, so accidental AWS
   keys, GitHub / Slack / Stripe tokens, JWTs, etc. show up under the
   normal `secrets in <bucket>` panel.

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--url` | (required) | Entry URL for the crawl. |
| `--max-pages` | 250 | Hard cap on URLs fetched in one run. |
| `--max-concurrency` | 10 | Parallel HTTP requests. |
| `--timeout` | 15.0 | Per-request HTTP timeout (seconds). |
| `--user-agent` | `cloud-service-enum/2.0 (+unauth)` | User-Agent header. |
| `--scope-host` | (none) | Additional hostname to treat as in-scope (repeat). |
| `--probe / --no-probe` | on | Run safe `GetId` / `InitiateAuth` probes. |
| `--probe-signup` | off | Also run the `SignUp` probe (opt-in). |
| `--report-format` | `json` | Repeatable: json, csv, xml, xlsx, docx, pdf. |
| `--output-dir` | `./reports` | Where reports are written. |

### Output shape

The command produces a normal `EnumerationRun` with one
`ServiceResult(service="unauth-cognito")`. The terminal renderer
groups results into three resource kinds:

- `user_pool` — `id`, `region`, `client_ids`, `first_seen_url`,
  optional `auth_flows` / `signup_enabled` / `probes` summaries.
- `identity_pool` — `id`, `region`, `first_seen_url`,
  `unauth_allowed` (yes/no), optional `sample_identity_id`,
  `probes` summary.
- `crawl_summary` — `id` (target URL), `pages_fetched`, `js_files`,
  `kb_downloaded`, `hosts`, `failed_pages`, plus an embedded
  `secrets_found` list when the body sweep matches anything.

Every field is also present in the JSON / CSV / XLSX / XML / DOCX /
PDF reports written to `--output-dir`.

### Safety notes

- **No write operations.** `GetId` reads pool config; `InitiateAuth`
  is sent with throwaway credentials; `SignUp` is sent with a
  password that AWS rejects before a user record is created.
- **Read-only crawl.** The crawler only ever issues `GET` requests
  and follows in-scope hosts. If you need to limit it further, lower
  `--max-pages` or set `--max-concurrency 1`.
- **Probes are not stealthy.** They appear in the target's CloudTrail
  log as `cognito-idp.amazonaws.com` / `cognito-identity.amazonaws.com`
  events. Don't run them against estates you don't own without
  authorisation.

## `cse aws unauth s3`

Crawls a web app (optional) + probes a list of S3 buckets for public
access. Works in three input modes that compose freely:

- `--url <URL>` — crawl the page and pull bucket names out of every
  JS / HTML / JSON body (`bucket.s3.amazonaws.com`, path-style,
  `s3://…`, website endpoints).
- `--bucket <NAME>` — probe one bucket directly. Repeatable.
- `--bruteforce` — combine each `--bruteforce-prefix` with every
  suffix in a wordlist to generate candidate names. Defaults to the
  bundled `s3-bucket-suffixes.txt`; override with
  `--bruteforce-wordlist <PATH>`.

```bash
# Crawl + explicit bucket
cse aws unauth s3 --url https://app.example.com --bucket acme-assets

# Small bruteforce pass
cse aws unauth s3 --bruteforce --bruteforce-prefix acme --bruteforce-prefix acme-prod
```

### Probes per bucket

Every candidate bucket gets the same probe suite against the public S3
REST API (all anonymous, all read-only):

| Probe | HTTP call | What it flags |
|-------|-----------|---------------|
| Existence | `HEAD /` | `exists` / `no_such_bucket` / `all_access_disabled` / `access_denied` / cross-region redirect. Captures `x-amz-bucket-region`. |
| Public list | `GET /?list-type=2&max-keys=100` | Anonymous `ListObjectsV2`. If `200`, captures the first N object keys. |
| ACL | `GET /?acl` | Public ACL document exposure. |
| Policy | `GET /?policy` | Public bucket policy document exposure. |
| Website | `GET /?website` | Public website-config exposure. |
| CORS | `GET /?cors` | Public CORS-config exposure. |

When a bucket returns a public listing, text-like keys (`.txt`,
`.json`, `.env`, `.yaml`, `.ini`, `.sql`, …) are sampled with a capped
`Range` request (`--max-object-size-kb`, default 500 KB) and run
through `core.secrets.scan_text`. Matches show up under the bucket's
`secrets_found` panel and under a dedicated `bucket_object` resource
for each file.

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--url` | (none) | Entry URL to crawl for bucket references. |
| `--bucket` | (none) | Explicit bucket to probe (repeatable). |
| `--bruteforce` | off | Enable wordlist bucket-name enumeration. |
| `--bruteforce-prefix` | (none) | Required when `--bruteforce` is on. Repeatable. |
| `--bruteforce-wordlist` | bundled | Suffix wordlist path. |
| `--max-objects` | 100 | Max public objects sampled per bucket. |
| `--max-object-size-kb` | 500 | Max bytes fetched per sampled object. |
| Crawler knobs | `--max-pages 250 --max-concurrency 10 --timeout 15 --user-agent … --scope-host …` | Same as `cognito`. |

At least one of `--url`, `--bucket`, or `--bruteforce` is required.

### Output shape

One `ServiceResult(service="unauth-s3")` with these resource kinds:

- `bucket` — `name`, `region`, `exists`, `public_list`, `public_acl`,
  `public_policy`, `public_website`, `public_cors`, `objects_sampled`,
  `probes` summary, optional `secrets_found`.
- `bucket_object` — emitted per sampled object. `bucket`, `key`,
  `size`, `bytes_scanned`, `secret_count`.
- `crawl_summary` — when `--url` was supplied.
- `bruteforce_summary` — when `--bruteforce` was supplied.

### Safety notes

- All probes are HTTP `GET`/`HEAD` — no writes, no deletes.
- Probes hit the target account's CloudTrail (`s3.amazonaws.com`
  `ListBucket` / `GetBucketAcl` / `GetBucketPolicy` events).
  Bruteforce in particular is noisy — don't run it against estates
  you don't own without authorisation.
- Bucket-name bruteforce generates `prefix-suffix`, `prefix.suffix`,
  `prefixsuffix`, and `suffix-prefix` for every prefix / suffix pair.
  A single prefix + the bundled wordlist is ~280 candidates.

## `cse aws unauth api-gateway`

Crawls a web app (optional) + probes every discovered
`execute-api.amazonaws.com` or `lambda-url.on.aws` endpoint for public
routes, accidentally-exposed OpenAPI specs, and CORS misconfiguration.

```bash
cse aws unauth api-gateway --url https://app.example.com
cse aws unauth api-gateway \
  --api-url https://abcd123456.execute-api.us-east-1.amazonaws.com/prod \
  --api-url https://fnx7yq3abc.lambda-url.eu-west-1.on.aws
```

### Classification

URLs are classified by regex before any HTTP call:

- `https://<10-char>.execute-api.<region>.amazonaws.com[/<stage>]` —
  REST API if a stage is present, HTTP API otherwise.
- `wss://<10-char>.execute-api.<region>.amazonaws.com` — WebSocket
  API. Detection only; no active handshake.
- `https://<alias>.lambda-url.<region>.on.aws` — Lambda Function URL.

### Probes per endpoint

| Probe | HTTP call | What it flags |
|-------|-----------|---------------|
| Root | `GET /` (or `/<stage>/` for REST) | `Missing Authentication Token` → IAM-enforced. `Not Found` → stage exists but no matching route. `200/301/302` → root is public. |
| OpenAPI leak | `GET /openapi.json` + `/swagger.json` + `/api-docs` + `/v1/openapi.json` (+ stage-prefixed variants) | Captures the JSON body if `200` and renders it under the existing `definition` panel. |
| Stages (REST only) | `GET /<candidate>/` for `prod`, `dev`, `staging`, `test`, `v1`, `v2`, `api` | Any non-404 response counts as "stage exists". |
| CORS | `OPTIONS /` with `Origin: https://example.invalid` | Flags `Access-Control-Allow-Origin: *` and echoed-origin + `Access-Control-Allow-Credentials: true`. |
| Lambda URL fingerprint | `GET /` with forged `Origin` | `200/301/302` → `AUTH_TYPE=NONE`. `403 Forbidden` / `Missing Authentication Token` → `AWS_IAM`. |

WebSocket endpoints are recorded but not handshaked — upgrading
`wss://` unauthenticated is too easy to get wrong.

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--url` | (none) | Entry URL to crawl for API references. |
| `--api-url` | (none) | Explicit endpoint to probe (repeatable). |
| Crawler knobs | same as `cognito`/`s3` | `--max-pages`, `--max-concurrency`, `--timeout`, `--user-agent`, `--scope-host`. |

At least one of `--url` or `--api-url` is required.

### Output shape

One `ServiceResult(service="unauth-apigw")` with these resource
kinds:

- `api_gateway` — `api_id`, `region`, `type` (`rest` / `http` /
  `websocket`), `url`, `auth_required`, `stages_detected`,
  `openapi_exposed`, `cors_wildcard`, `cors_credentials`, optional
  `definition` (captured OpenAPI body).
- `lambda_function_url` — `alias`, `region`, `url`, `auth_type`
  (`NONE` / `AWS_IAM`), `cors_wildcard`, `cors_credentials`.
- `crawl_summary` — when `--url` was supplied.

### Safety notes

- All probes are `GET` / `OPTIONS` requests with no request body.
- Probes show up under the target account's CloudTrail / Lambda URL
  access logs. Don't run them against estates you don't own without
  authorisation.
- Request-body fuzzing and authenticated API Gateway introspection
  are out of scope for this command.
