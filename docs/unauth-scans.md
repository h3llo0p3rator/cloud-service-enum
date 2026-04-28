# Unauthenticated cloud recon

Some cloud services leak attacker-useful identifiers through the
client-side bundles of their consuming web apps — or publish them to
predictable public endpoints that don't require credentials to reach.
The `cse <provider> unauth` sub-trees wrap those recon flows behind a
single CLI: no cloud credentials are required on the scanner side.

Ten commands are currently wired up across three providers:

- [`aws unauth cognito`](#cse-aws-unauth-cognito) — user / identity pool
  + client id hunt.
- [`aws unauth s3`](#cse-aws-unauth-s3) — bucket hunt, public-access
  probes, optional wordlist bruteforce + object sampling.
- [`aws unauth api-gateway`](#cse-aws-unauth-api-gateway) — REST / HTTP
  / WebSocket API Gateway + Lambda Function URL fingerprinting.
- [`aws unauth beanstalk`](#cse-aws-unauth-beanstalk) — Elastic
  Beanstalk CNAME hunt + optional DNS resolution.
- [`aws unauth cloudfront`](#cse-aws-unauth-cloudfront) — Host / Origin
  override cache-key-confusion probe against a single URL.
- [`aws unauth lambda-url`](#cse-aws-unauth-lambda-url) — extract +
  probe `lambda-url.on.aws` endpoints, classifying auth mode.
- [`azure unauth storage`](#cse-azure-unauth-storage) — storage-account
  hunt across all five endpoints (blob / file / queue / table / dfs)
  plus built-in blob-container probes and blob sampling.
- [`azure unauth appservice`](#cse-azure-unauth-appservice) — Azure
  App Service (`*.azurewebsites.net`) discovery + canonical leak
  probes (Kudu anonymous access, `/.git/HEAD`, `/.env`, …).
- [`gcp unauth bucket`](#cse-gcp-unauth-bucket) — GCS bucket hunt with
  metadata / listing / IAM probes. The metadata response leaks the
  owning `projectNumber`, which is the closest thing GCP has to S3
  account-id attribution.
- [`gcp unauth cloudrun`](#cse-gcp-unauth-cloudrun) — extract
  `*.run.app` URLs + classify their auth posture (public vs
  IAM-gated).

Every command shares the same crawler + credential regex sweep:
extraction regexes and probes differ per service, but the
`--url` → crawl → extract pipeline is identical. The crawler knobs
(`--max-pages`, `--max-concurrency`, `--timeout`, `--user-agent`,
`--scope-host`) behave the same way in every command.

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
| `--download / --no-download` | off | Enable object downloads into `loot/<bucket>/...`. |
| `--download-all` | off | Download all listed objects from each targeted bucket. |
| `--file` | (none) | Specific object key(s) to download (repeatable). |
| `--files` | (none) | Comma-separated object keys to download. |
| Crawler knobs | `--max-pages 250 --max-concurrency 10 --timeout 15 --user-agent … --scope-host …` | Same as `cognito`. |

At least one of `--url`, `--bucket`, or `--bruteforce` is required.

### Output shape

One `ServiceResult(service="unauth-s3")` with these resource kinds:

- `bucket` — `name`, `region`, `exists`, `public_list`, `public_acl`,
  `public_policy`, `public_website`, `public_cors`, `objects_sampled`,
  `probes` summary, optional `secrets_found`.
- `bucket_object` — emitted per sampled object. `bucket`, `key`,
  `size`, `bytes_scanned`, `secret_count`.
- `downloaded_object` — emitted per downloaded object. Includes
  `loot_path` under `loot/<bucket>/...`.
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

## `cse azure unauth storage`

Crawls a web app (optional) + probes a list of Azure storage accounts
for public access across every service endpoint. Works in three input
modes that compose freely:

- `--url <URL>` — crawl the page and pull storage-account + container
  references out of every text body. The extractor understands
  `<acct>.<blob|file|queue|table|dfs>.core.windows.net`,
  `<acct>.z<n>.web.core.windows.net` (static-website), and path-style
  `<acct>.blob.core.windows.net/<container>` URLs.
- `--account <NAME>` — probe a specific storage account. Repeatable.
- `--bruteforce` — combine each `--bruteforce-prefix` with every
  suffix in a wordlist. Azure storage-account names are alnum-only,
  so candidates come out as `<prefix><suffix>`, `<suffix><prefix>`,
  and `<prefix><1|2|3><suffix>`. Defaults to the bundled
  `azure-storage-account-suffixes.txt`.

```bash
# Crawl + explicit accounts
cse azure unauth storage --url https://app.example.com --account acmeprod

# Bruteforce a shortlist of prefixes
cse azure unauth storage \
  --bruteforce --bruteforce-prefix acme --bruteforce-prefix acmeprod
```

### Account-level probes

Every candidate account is probed across all five storage services
(blob / file / queue / table / dfs) plus a small set of
static-website zone hostnames:

| Probe | HTTP call | What it flags |
|-------|-----------|---------------|
| Blob | `GET /?comp=list` against `*.blob.core.windows.net` | 200 + `<EnumerationResults>` → account-level blob listing is public. 400/403 with the Azure server banner → account exists but listing is denied. |
| File | `GET /?comp=list` against `*.file.core.windows.net` | Same signal shape as blob. |
| Queue | `GET /?comp=list` against `*.queue.core.windows.net` | Same signal shape as blob. |
| Table | `GET /Tables` against `*.table.core.windows.net` | 400 `InvalidAuthenticationInfo` → table service exists. |
| DFS (Data Lake Gen2) | `GET /?resource=account` against `*.dfs.core.windows.net` | Same signal shape as blob. |
| Static website | `HEAD` against `*.z1…z36.web.core.windows.net` | Any Azure-server response → static hosting enabled. |

An account is surfaced in the terminal output when **at least one**
surface returned a definitive "service exists" response. DNS failures,
TLS handshake failures, and anything else are treated as noise and
suppressed — only actionable rows are rendered. Bruteforce counters
still see every candidate.

### Container-level probes

Whenever an account exists, the runner additionally probes a small
built-in wordlist of common container names
(`backup`, `logs`, `prod`, `public`, `secrets`, `terraform`,
`uploads`, `$web`, …) plus any containers surfaced by the crawl or
supplied explicitly via `--container <acct>/<name>` or bare
`--container <name>` (applied against every `--account`).

| Probe | HTTP call | What it flags |
|-------|-----------|---------------|
| Public listing | `GET .../<container>?restype=container&comp=list&maxresults=100` | 200 + `<Blob>` entries → public listing. Captures the first N blob names. |
| ACL | `GET .../<container>?restype=container&comp=acl` | 200 response reveals the `x-ms-blob-public-access` header (`blob` / `container` / `none`). |
| Metadata | `GET .../<container>?restype=container` | 200 leaks `x-ms-meta-*` headers and `Last-Modified`. |

Only containers with an actionable signal (public listing, 200
metadata, or a public access level other than `none`) are rendered.

### Blob sampling

For every container with a public listing, text-like blobs (`.txt`,
`.json`, `.env`, `.yaml`, `.ini`, `.sql`, …) are sampled with a capped
`Range` request (`--azure-scan-size-limit-kb`, default 500 KB) and run through
`core.secrets.scan_text`. Matches show up under the container's
`secrets_found` panel and as a dedicated `storage_blob` resource for
each file.

### SAS token extraction

Every crawled body is scanned for Azure SAS query-string patterns
(`?sv=…&sig=…`). Any hit is rendered under a dedicated
`sas_token_summary` resource with the signature portion redacted.

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--url` | (none) | Entry URL to crawl for account / container references. |
| `--account` | (none) | Explicit storage account (repeatable). |
| `--container` | (none) | `<acct>/<container>` or bare `<container>` (repeatable). |
| `--bruteforce` | off | Enable wordlist storage-account bruteforce. |
| `--bruteforce-prefix` | (none) | Required when `--bruteforce` is on. Repeatable. |
| `--bruteforce-wordlist` | bundled | Suffix wordlist path. |
| `--bruteforce-container` | off | Replace the built-in container wordlist with `--container-wordlist`. |
| `--container-wordlist` | (none) | Required with `--bruteforce-container`. |
| `--max-blobs` | 100 | Max public blobs sampled per container. |
| `--max-blob-size-kb` | 500 | Max bytes fetched per sampled blob. |
| `--azure-scan-file-limit` | (none) | Azure-named alias for `--max-blobs`. |
| `--azure-scan-size-limit-kb` | (none) | Azure-named alias for `--max-blob-size-kb`. |
| `--download / --no-download` | off | Enable blob downloads into `loot/<container>/...`. |
| `--download-all` | off | Download all listed blobs from each targeted container. |
| `--file` | (none) | Specific blob key(s) to download (repeatable). |
| `--files` | (none) | Comma-separated blob keys to download. |
| Crawler knobs | same as AWS commands | `--max-pages`, `--max-concurrency`, `--timeout`, `--user-agent`, `--scope-host`. |

At least one of `--url`, `--account`, or `--bruteforce` is required.

### Output shape

One `ServiceResult(service="unauth-storage")` with these resource
kinds:

- `storage_account` — `name`, `surfaces` (comma-joined list of live
  services), per-surface `*_list_public` / `*_exists` flags,
  `static_website` URL, `first_seen_url`, `probes` summary.
- `storage_container` — `account`, `container`, `public_list`,
  `public_access_level`, `metadata_public`, `blobs_listed`,
  `probes`, optional `secrets_found`.
- `storage_blob` — per sampled blob: `account`, `container`, `key`,
  `size`, `bytes_scanned`, `secret_count`.
- `downloaded_object` — per downloaded blob with `loot_path` under
  `loot/<container>/...`.
- `sas_token_summary` — every leaked SAS token (signatures redacted).
- `crawl_summary` — when `--url` was supplied.
- `bruteforce_summary` — when `--bruteforce` was supplied.

### Safety notes

- Every probe is an anonymous `GET` / `HEAD` — no writes, no deletes.
- Probes show up in the target account's Storage Analytics logs as
  anonymous `ListBlobs` / `GetContainerProperties` / `GetACL` events.
  Bruteforce is noisy by construction — don't run it against estates
  you don't own without authorisation.
- SAS tokens are reported with their signatures redacted. They are
  never re-used by the tool, even when they look valid.

## `cse gcp unauth bucket`

Crawls a web app (optional) + probes a list of GCS buckets for public
metadata, listing, and IAM exposure. Works in three input modes that
compose freely:

- `--url <URL>` — crawl the page and pull bucket names out of every
  text body (`<bucket>.storage.googleapis.com`,
  `storage.googleapis.com/<bucket>`, `gs://<bucket>`,
  Firebase `<bucket>.appspot.com`).
- `--bucket <NAME>` — probe one bucket directly. Repeatable.
- `--bruteforce` — combine each `--bruteforce-prefix` with every
  suffix in a wordlist. GCS permits `_`, so candidates come out as
  `<p>-<s>`, `<p>.<s>`, `<p><s>`, `<p>_<s>`, and `<s>-<p>`.
  Defaults to the bundled `gcs-bucket-suffixes.txt`.

```bash
# Crawl + explicit bucket
cse gcp unauth bucket --url https://app.example.com --bucket acme-assets

# Small bruteforce pass
cse gcp unauth bucket \
  --bruteforce --bruteforce-prefix acme --bruteforce-prefix acme-prod
```

### Probes per bucket

Every candidate bucket gets the same probe suite against the public
GCS JSON API (all anonymous, all read-only):

| Probe | HTTP call | What it flags |
|-------|-----------|---------------|
| Metadata | `GET /storage/v1/b/<bucket>` | 200 exposes **`projectNumber`** (the owning project — the GCP equivalent of S3's missing account-id attribution), `location`, `storageClass`, `iamConfiguration.uniformBucketLevelAccess`, `website.mainPageSuffix`, `cors`. 404 → bucket doesn't exist. 401/403 → bucket exists but metadata is locked down. |
| Public list | `GET /storage/v1/b/<bucket>/o?maxResults=100` | 200 → anonymous listing allowed. Captures the first N object names. |
| IAM policy | `GET /storage/v1/b/<bucket>/iam` | 200 → public IAM read. Flags `allUsers` / `allAuthenticatedUsers` bindings explicitly; full binding list is rendered via the existing role-binding panel. |
| Website | `GET https://<bucket>.storage.googleapis.com/` | 200/301/302 → bucket-backed website enabled. |
| CORS | Captured from the metadata response. | Wildcard `Origin: *` rules are flagged. |

Only buckets with an authoritative "exists" response are surfaced in
the terminal. Everything else (DNS failures, 404s, TLS errors) is
suppressed — bruteforce counters still see every candidate.

### Object sampling

For every bucket that permits anonymous listing, text-like objects
are sampled with a capped `Range` request (`--max-object-size-kb`,
default 500 KB) and run through `core.secrets.scan_text`. Matches show
up under the bucket's `secrets_found` panel and as a dedicated
`gcs_object` resource for each file.

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
| `--download / --no-download` | off | Enable object downloads into `loot/<bucket>/...`. |
| `--download-all` | off | Download all listed objects from each targeted bucket. |
| `--file` | (none) | Specific object key(s) to download (repeatable). |
| `--files` | (none) | Comma-separated object keys to download. |
| Crawler knobs | same as AWS / Azure commands | `--max-pages`, `--max-concurrency`, `--timeout`, `--user-agent`, `--scope-host`. |

At least one of `--url`, `--bucket`, or `--bruteforce` is required.

### Output shape

One `ServiceResult(service="unauth-bucket")` with these resource
kinds:

- `gcs_bucket` — `name`, `project_number`, `location`,
  `storage_class`, `uniform_access`, `public_list`, `public_iam`,
  `website`, `website_main_page`, `cors_wildcard`,
  `cors_credentials`, `first_seen_url`, `probes` summary, optional
  `iam_bindings` (rendered via the role-binding panel) and
  `secrets_found`.
- `gcs_object` — per sampled object: `bucket`, `key`, `size`,
  `bytes_scanned`, `secret_count`.
- `downloaded_object` — per downloaded object with `loot_path` under
  `loot/<bucket>/...`.
- `crawl_summary` — when `--url` was supplied.
- `bruteforce_summary` — when `--bruteforce` was supplied.

### Safety notes

- All probes are anonymous `GET` requests — no writes, no deletes.
- Probes show up in the target project's GCS access logs and in any
  Data Access audit log destinations that capture bucket metadata
  reads. Bruteforce is noisy — don't run it against estates you don't
  own without authorisation.
- The IAM probe deliberately stops at reading the policy document.
  It never attempts to evaluate whether a given role grants anything
  useful to the scanning principal — that's the authenticated scan's
  job.

## `cse aws unauth beanstalk`

Extracts Elastic Beanstalk environment hostnames from a crawled app and
optionally resolves them to confirm the EB environment is still live.

```bash
cse aws unauth beanstalk --url https://app.example.com
cse aws unauth beanstalk --hostname myapp.us-east-1.elasticbeanstalk.com
```

### What it does

1. **Crawl** (`--url`) — same-origin crawl that regex-matches
   `<env>[.<region>].elasticbeanstalk.com` in every text body.
2. **Direct inputs** — `--hostname` accepts explicit Beanstalk hosts
   (repeatable); useful when you already know the environment name.
3. **DNS resolution** — each hit is resolved via asyncio's DNS
   resolver. The resolver captures the CNAME target (usually
   `awseb-<env>.<region>.elb.amazonaws.com`) and raw A records, and
   flags whether the target still looks like an EB-controlled load
   balancer.

Failed lookups (no DNS records at all) are suppressed from the
terminal to avoid drowning the output with dead environments.

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--url` | (none) | Entry URL for the crawl. |
| `--hostname` | (none) | Explicit Beanstalk hostname (repeatable). |
| Crawler knobs | same as other unauth commands | `--max-pages`, `--max-concurrency`, `--timeout`, `--user-agent`, `--scope-host`. |

At least one of `--url` or `--hostname` is required.

### Output shape

One `ServiceResult(service="unauth-beanstalk")` with these resource
kinds:

- `eb-env` — `hostname`, `name` (environment name guess), `region`,
  `cname_target`, `is_eb_controlled` (yes/no/-), `resolved_ips`.
- `crawl_summary` — when `--url` was supplied.

## `cse aws unauth cloudfront`

Fires a triplet of probes at a single URL to surface CloudFront cache
key confusion and CORS misconfiguration: a baseline request, one with
a custom `Host` header, and one with a forged `Origin` header. Each
response is diffed against the baseline.

```bash
cse aws unauth cloudfront --url https://d123abcd.cloudfront.net/
cse aws unauth cloudfront --url https://assets.example.com \
    --host-override admin.example.com
```

### What it does

1. **Baseline** — `GET /` with the scanner's default User-Agent.
2. **Host override** — `GET /` with `Host: <alt>` (defaults to a
   throwaway `evil.example`). A divergent body size or cache header
   is flagged as a potential cache-key confusion issue.
3. **Origin override** — `GET /` with `Origin: https://evil.example`.
   Flags `Access-Control-Allow-Origin: *` and echoed-origin +
   `Access-Control-Allow-Credentials: true` combos.

All three responses capture the `x-amz-cf-id`, `x-amz-cf-pop`,
`via`, and any cache headers for forensic clarity. The runner
never mutates state: probes are plain `GET`s.

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--url` | (required) | URL to probe. |
| `--host-override` | `evil.example` | Alternate Host header. |
| `--origin-override` | `https://evil.example` | Origin header for CORS probe. |
| `--max-concurrency` | 5 | Currently unused (probes are sequential). |
| `--timeout` | 20 | Per-request HTTP timeout. |
| `--user-agent` | `cloud-service-enum/2.0 (+unauth cloudfront)` | User-Agent header. |

### Output shape

One `ServiceResult(service="unauth-cloudfront")` with a
`cf-response` resource per probe (`baseline`, `host-override`,
`origin-override`), each carrying `status`, `body_size`,
`cache_header`, `x_amz_cf_id`, `x_amz_cf_pop`, `via_header`,
`allow_origin`, and `diff_vs_baseline`.

## `cse aws unauth lambda-url`

Extracts `*.lambda-url.<region>.on.aws` URLs from a crawled app (or
takes explicit `--lambda-url` inputs) and probes each with a HEAD +
GET pair to classify the function's auth mode.

```bash
cse aws unauth lambda-url --url https://app.example.com
cse aws unauth lambda-url \
    --lambda-url https://abcd.lambda-url.us-east-1.on.aws
```

### What it does

1. **Crawl + extract** — every text body is regex-matched for Lambda
   Function URLs.
2. **Direct inputs** — `--lambda-url` (repeatable).
3. **Probe** — HEAD + small GET. Auth mode is classified as `NONE`
   when the function returns a 2xx body, or `AWS_IAM` when the
   response is 401/403 with the canonical
   `Missing Authentication Token` body.

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--url` | (none) | Entry URL for the crawl. |
| `--lambda-url` | (none) | Explicit Lambda Function URL (repeatable). |
| Crawler knobs | same as other unauth commands | `--max-pages`, `--max-concurrency`, `--timeout`, `--user-agent`, `--scope-host`. |

At least one of `--url` or `--lambda-url` is required.

### Output shape

One `ServiceResult(service="unauth-lambda-url")` with
`lambda-url` resources carrying `url`, `function_hint`, `region`,
`auth_mode` (`NONE` / `AWS_IAM`), `head_status`, `get_status`,
`request_id`, `cors_wildcard`, `cors_credentials`, plus optional
`crawl_summary`.

## `cse azure unauth appservice`

Extracts `*.azurewebsites.net` and `*.scm.azurewebsites.net`
hostnames from a crawled app and probes each for the canonical
App Service health path plus a small set of known config-leak
paths.

```bash
cse azure unauth appservice --url https://portal.example.com
cse azure unauth appservice --hostname demo-site.azurewebsites.net
```

### What it does

1. **Crawl + extract** — every text body is regex-matched for
   `*.azurewebsites.net` hosts; both primary sites and their `.scm.`
   companions are captured.
2. **Direct inputs** — `--hostname` accepts explicit App Service
   hostnames (repeatable); passing the primary site auto-derives
   its `.scm.` companion.
3. **Probe** — for each host:
   - `/robots933456.txt` — the canonical App Service health path. A
     404 from the EasyAuth / Antares frontend is proof the site
     exists even when the application denies requests.
   - `/.git/HEAD`, `/.env`, `/package.json`, `/appsettings.json`,
     `/web.config`, `/wwwroot/.env` — known config-leak paths.
   - `/api/siteextensions` on the `.scm.` companion — 200 here
     indicates Kudu is anonymously reachable, which is high
     severity.

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--url` | (none) | Entry URL for the crawl. |
| `--hostname` | (none) | Explicit App Service hostname (repeatable). |
| Crawler knobs | same as other unauth commands | `--max-pages`, `--max-concurrency`, `--timeout`, `--user-agent`, `--scope-host`. |

At least one of `--url` or `--hostname` is required.

### Output shape

One `ServiceResult(service="unauth-appservice")` with these
resource kinds:

- `azure-webapp` — `hostname`, `scm_hostname`, `site_name`, `exists`,
  `kudu_anonymous` (yes/no/-), plus a `probes` table with one row per
  probed path (`path`, `status`, `length`, `leak_indicator`).
- `crawl_summary` — when `--url` was supplied.

## `cse gcp unauth cloudrun`

Extracts `*.run.app` URLs from a crawled app and classifies each
as public vs IAM-gated. Cloud Run exposes a canonical
`x-cloud-trace-context` response header; the presence of that
header plus the HTTP status code drives the classification.

```bash
cse gcp unauth cloudrun --url https://app.example.com
cse gcp unauth cloudrun \
    --run-url https://svc-abc123-uc.a.run.app
```

### What it does

1. **Crawl + extract** — every text body is regex-matched for
   `*.a.run.app` (default Cloud Run URL shape) and `*.run.app`
   (custom domain shape).
2. **Direct inputs** — `--run-url` (repeatable).
3. **Probe** — HEAD + GET against `/`. Classification:
   - 2xx / 3xx + `x-cloud-trace-context` → `public`.
   - 401 / 403 + `x-cloud-trace-context` → `iam-gated` (service
     exists but the invoker lacks `run.services.invoke`).
   - Other responses → `proxy (<status>)` — typically an upstream
     load balancer or Firebase Hosting domain.

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--url` | (none) | Entry URL for the crawl. |
| `--run-url` | (none) | Explicit Cloud Run URL (repeatable). |
| Crawler knobs | same as other unauth commands | `--max-pages`, `--max-concurrency`, `--timeout`, `--user-agent`, `--scope-host`. |

At least one of `--url` or `--run-url` is required.

### Output shape

One `ServiceResult(service="unauth-cloudrun")` with these resource
kinds:

- `cloudrun_service` — `url`, `name`, `region_hint`, `auth_mode`
  (`public` / `iam-gated` / `proxy (<status>)`), `is_cloud_run`,
  `head_status`, `get_status`, `cloud_trace`, `fingerprint_headers`
  (server / via / alt-svc when present), `first_seen_url`.
- `crawl_summary` — when `--url` was supplied.

### Safety notes

All new unauth probes in this section honour the same read-only
discipline as the older commands: no request body writes, no
authenticated handshakes, and every probe is either a HEAD or a
GET. The host override / origin override probes in
`cse aws unauth cloudfront` deliberately send syntactically valid
headers against the target URL — they never attempt to modify
cached content.
