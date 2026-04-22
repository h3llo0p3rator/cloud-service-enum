# Result schema

Every `cse <provider> enumerate` invocation produces a single
`EnumerationRun` document. Reports (`json`, `xlsx`, …) are just
serializations of this object, so if you write tooling against the tool
you only need to understand the shape below. All models are
[Pydantic v2](https://docs.pydantic.dev) models and accept unknown
fields (`extra = "allow"`), so services are free to attach extra
metadata without breaking existing consumers.

## `EnumerationRun`

| Field | Type | Description |
|-------|------|-------------|
| `provider` | `"aws" \| "azure" \| "gcp" \| "osint"` | Cloud provider or OSINT. |
| `scope` | `Scope` | Input parameters that constrained the run. |
| `identity` | `dict` | Principal/tenant/account identifier derived from the `test()` call of the authenticator. |
| `services` | `list[ServiceResult]` | One entry per enumerator that ran. |
| `started_at` / `finished_at` | ISO-8601 | UTC timestamps. |
| `duration_s` | `float` | Wall-clock total, rounded to 3dp. |

Convenience accessors:

- `run.resource_total()` — total number of resources across all services.
- `run.error_total()` — total non-fatal errors captured.
- `run.by_service()` — `dict[str, ServiceResult]`.

## `Scope`

| Field | Type | Description |
|-------|------|-------------|
| `provider` | `Provider` | Provider this scope applies to. |
| `regions` | `list[str]` | AWS regions (empty ⇒ enumerate all). |
| `subscription_ids` | `list[str]` | Azure subscription ids. |
| `project_ids` | `list[str]` | GCP projects. |
| `services` | `list[str]` | Enumerator names to run (empty ⇒ all registered). |
| `max_concurrency` | `int` | Default 10. |
| `timeout_s` | `float` | Per-service timeout. |
| `deep_scan` | `bool` | Force every service to run its medium-cost "deep" branch. Auto-enabled when `services` is set on the CLI. See [docs/deep-scans.md](deep-scans.md). |
| `secret_scan` | `bool` | Run regex secret-scanning on every text surface a deep branch fetches (env-var maps, startup scripts, workflow definitions, runbook code, S3/GCS objects). Auto-enabled when `services` is set. |
| `iam_policy_bodies` | `bool` | Fetch full IAM policy JSON for AWS users/groups/roles/policies (default `True`). |
| `s3_secret_scan` | `bool` | Legacy alias of `secret_scan` for the `s3` enumerator. |
| `s3_scan_file_limit` | `int` | Max objects per bucket scanned for secrets (default 100). Also used by GCS. |
| `s3_scan_size_limit_kb` | `int` | Max object size scanned for secrets (default 500 KB). Also used by GCS. |

## `ServiceResult`

Free-form, but consumers can always rely on the following:

| Field | Type | Description |
|-------|------|-------------|
| `provider` | `Provider` | Matches `run.provider`. |
| `service` | `str` | Canonical enumerator name (e.g. `"s3"`, `"aks"`, `"iam"`). |
| `resources` | `list[dict]` | One dict per discovered resource — each has at least `kind`, `id`, and usually `name` / `region`. |
| `cis_fields` | `dict` | Aggregate values used to evaluate CIS controls (e.g. `public_bucket_count`, `mfa_enabled_users`). |
| `errors` | `list[str]` | Non-fatal error messages. |
| `started_at` / `finished_at` / `duration_s` | timestamps | Per-service timing. |
| `ok` | `bool` | `True` if `errors` is empty. |
| `count` | `int` | `len(resources)`. |

## Resource dicts

Services agree on three conventional keys in every resource dict:

- `kind` — a short, lowercase string (`"bucket"`, `"vm"`, `"role"`, …)
- `id` — a provider-unique id (ARN, resource id, project-qualified name)
- `name` — human-readable name (may equal `id`)
- `region` (optional) — present on regional resources

Everything else is service-specific. The enumerator free-attaches whatever
CIS-relevant fields it was able to pull (e.g. `encryption`, `public_access`,
`key_rotation_days`, `retention_days`, …). See individual files under
`src/cloud_service_enum/{aws,azure,gcp}/services/` for the exact shape each
service returns.

### Deep-scan resource fields

When a service runs in deep mode (see [docs/deep-scans.md](deep-scans.md)),
resource dicts may carry any of the following extra keys. The terminal
renderer recognises each one and prints a dedicated panel:

| Key | Type | Rendered as |
|-----|------|-------------|
| `policy_document` | `dict \| list` | JSON-syntax policy panel (`policy: <name>`). |
| `env_vars` | `dict[str, str]` | Masked key/value panel (`env: <name>`). |
| `app_settings` | `dict[str, str]` | Masked key/value panel (`settings: <name>`). |
| `connection_strings` | `dict[str, str]` | Masked key/value panel (`connections: <name>`). |
| `firewall_rules` | `list[dict]` | Tabular rule list (`firewall: <name>`). |
| `role_bindings` | `list[dict]` | Principal/role/condition table (`iam: <name>`). |
| `definition` (+ `definition_language`) | `str \| dict` | Syntax-highlighted code panel (`definition: <name>`). |
| `script` / `startup_script` / `user_data` (+ `script_language`) | `str` | Syntax-highlighted code panel. |
| `secrets_found` | `list[dict]` | Red bordered findings table (`secrets in <name>`). |
| `scan_files_*` / `scan_bytes_scanned` | `int` | Bucket/object scan stats panel (`scan: <name>`). |

Reports (`json`, `xlsx`, …) preserve every key verbatim.

## OSINT

For `cse osint`, `services` contains a single result with `service="domains"`.
Each resource entry has `kind="domain"` and a `records` dict grouping DNS
answer types (A/AAAA/CNAME/MX/TXT). The `cis_fields` block summarizes the
run (`subdomain_count`, `whois`, `azure_tenant_id`, `brute_force_hits`,
`ct_hits`).
