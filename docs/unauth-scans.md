# Unauthenticated AWS recon

Some AWS services leak attacker-useful identifiers through the
client-side bundles of their consuming web apps. The `cse aws unauth`
sub-tree wraps the recon flows for those leaks behind a single CLI:
no AWS credentials are required.

The first (and currently only) command is `cognito`.

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
