# Per-service deep scans

Every cloud service enumerator has two modes:

- **Shallow / metadata** — always on. Cheap inventory listing
  (resource id, name, region, encryption flags, public-access flags,
  CIS-relevant booleans). Safe to run across every service in an
  account without blowing up API quotas.
- **Deep** — opt-in per-service. Fetches the data an attacker would
  pivot on once they know the resource exists: IAM policy bodies,
  Lambda env-vars, EC2 user-data, Logic App / Step Function
  definitions, runbook scripts, KMS key policies, RBAC role
  bindings, firewall rule contents, etc. Every text surface fetched
  in deep mode can additionally be regex-scanned for credentials.

The intent is that a focused single-service run reads almost like a
small audit script for that service, while a broad
`cse aws enumerate` (no `--service` flag) stays fast and noise-free.

## Activation rules

| User input | `deep_scan` | `secret_scan` |
|------------|-------------|---------------|
| `cse aws enumerate` (no flags) | off | off |
| `cse aws enumerate --service iam` | **on** for `iam` only | **on** |
| `cse aws enumerate --service iam --service s3` | **on** for `iam` + `s3` | **on** |
| `cse aws enumerate --deep` | **on** for every service | off |
| `cse aws enumerate --deep --secret-scan` | **on** for every service | **on** |
| `cse aws enumerate --service s3 --no-secret-scan` | **on** for `s3` | off |

Same flags exist on the Azure and GCP CLIs (`cse azure enumerate`
and `cse gcp enumerate`).

The auto-enable rule lives in
`cloud_service_enum.clis.common.resolve_deep_flags`. Each service
checks its context's `is_focused_on()` helper to decide whether to
fetch the deep payload — services never need to know about the CLI
flags directly.

## What "deep" means per service

Below is a non-exhaustive map of what each enumerator pulls when
focused. Anything not listed here stays at metadata level even in
deep mode. The exact field names match the resource dict keys
documented in [`result-schema.md`](result-schema.md).

### AWS

| Service | Extra fields fetched in deep mode |
|---------|------------------------------------|
| `iam` | Full `policy_document` JSON for managed policies, inline policies on users/roles/groups, role trust policies. |
| `s3` | Bucket-level secret scan over text objects (regex on `.env`, `.json`, `.yaml`, …). Configurable via `s3_scan_file_limit` and `s3_scan_size_limit_kb`. |
| `lambda` | `env_vars` (regex-scanned), `policy_document`, `function_url`, `event_sources`. |
| `ec2` | `user_data` for instances and launch templates (decoded + scanned). |
| `cloudformation` | Stack `definition` (template body) and `stack_resources`. |
| `stepfunctions` | State machine `definition` JSON. |
| `kms` | Key `policy_document` and `grants`. Aliases always collected. |
| `sns` / `sqs` / `dynamodb` / `efs` / `secretsmanager` | Resource `policy_document`. SQS adds `dlq_source_queues` when focused. EFS adds mount targets / access points. |
| `cloudtrail` | Resolved S3 bucket `policy_document` for the trail destination. |
| `wafv2` | Full ACL rules as `policy_document` plus `protected_resources`. |
| `cloudfront` | Detailed `origins` and `lambda_at_edge` associations. |
| `route53` | Hosted-zone `records`. |
| `glue` | Job `script_location` + `script_language`, `env_vars` (job arguments + connection properties). |
| `acm` | Certificate + chain body as `definition`. |
| `opensearch` | Parsed `policy_document` for domain access policies + advanced security options. |
| `organizations` | Always collects policy `Content` (SCPs, tag policies, …) as `policy_document` plus targets and `delegated_administrators`. |
| `rds` | `MasterUsername` always; focused mode adds snapshot `shared_with` attributes and DB proxy auth details. |
| `eks` | Cluster `role_arn`; lists `access_entries`, `node_pools`, `fargate_profiles`. |

### Azure

**Managed identities are always surfaced** (no `--deep` needed) for every
Azure resource type that supports them. Each row gets an `identity`
column — one of `system`, `user(N)`, `system+user(N)`, or blank — plus
an `identity: <name>` panel listing the system-assigned principal id and
all user-assigned identity (UAMI) resource ids. This lets an auditor
correlate a compromised resource with downstream role assignments
without opening a second terminal. Covered services include
`automation`, `compute` (VMs), `appservice`, `containerapps`, `aks`,
`containerregistry`, `logicapps`, `apim`, `cosmosdb`, `sql`,
`postgresql`, `storage`, `servicebus`, `eventhubs`, `eventgrid`,
`appgateway`, `frontdoor`, and anything exposed by the generic
`resources` enumerator when focused.

| Service | Extra fields fetched in deep mode |
|---------|------------------------------------|
| `automation` | New module. Runbook `script` + `script_language` (regex-scanned), `schedule` metadata, `credential` metadata, unencrypted `variable` values. |
| `storage` | Account `keys` (masked into `env_vars`), `management_policy`, `private_endpoints`, optional blob downloads into `loot/<container>/...` when `--download` is enabled on `cse azure enumerate --service storage`; download auth supports either ARM key lookup or direct account-key auth via `--storage-account-key` / `AZURE_STORAGE_KEY` (with account from `--account` or `AZURE_STORAGE_ACCOUNT`). |
| `keyvault` | `access_policies` rendered as `role_bindings`. |
| `appservice` | `application_settings` (regex-scanned), `connection_strings`, `auth_settings_v2`, detailed `site_config`. |
| `containerapps` | Container `env_vars` (regex-scanned) + `secret_refs`. |
| `cosmosdb` | Account `keys` (masked) as `env_vars`. |
| `aks` | `node_pools`, `node_resource_group`, `workload_identity` flag. |
| `logicapps` | Workflow `definition` JSON. |
| `sql` / `postgresql` | `firewall_rules`, `auditing` policy, notable server config flags as `env_vars`. |
| `apim` | `apis` list and named-value `env_vars` (with secret detection). |
| `containerregistry` | Admin `credentials` (when admin user enabled), `webhooks`. |
| `servicebus` / `eventhubs` / `eventgrid` | Authorization-rule `connection_strings` masked into `env_vars`. Eventhubs also lists `event_hubs`; eventgrid lists topics + domains separately. |
| `compute` | Decoded `startup_script` from VM `custom_data` (regex-scanned), VM extension settings, `admin_username`. |
| `network` | All NSG rules as `firewall_rules` (not just world-open). |
| `firewall` | Application/network/NAT rule collections + firewall-policy rule collection groups. |
| `appgateway` | Frontend IP configs, HTTP listeners, backend pools. |
| `frontdoor` | AFD `endpoints` + `security_policies`. |
| `loganalytics` | Workspace `keys` (masked), data sources. |
| `sentinel` | Scheduled `alert_rules` (with KQL `query`) + `data_connectors`. |
| `policy` | Full assignment `policy_document` (parameters + non-compliance messages). |
| `rbac` | Custom-role `policy_document` (permissions + assignable scopes). |
| `conditional_access` | Full conditions / grant / session controls as `policy_document`. |
| `graph` | Per-user `auth_methods`; per-group `members` and `owners`. |

### GCP

| Service | Extra fields fetched in deep mode |
|---------|------------------------------------|
| `iam` | Custom-role `policy_document`. Every service-account resource also gets its own `get_iam_policy` fetch: the resulting bindings are attached as `role_bindings` and summarised as an `impersonators` column (e.g. `tokenCreator(2)+user(1)`). Any principal holding `roles/iam.serviceAccountTokenCreator`, `roles/iam.serviceAccountUser`, `roles/iam.workloadIdentityUser`, `roles/iam.serviceAccountKeyAdmin`, `roles/iam.serviceAccountAdmin` or `roles/owner` on the SA is flagged because it represents an impersonation / privilege-escalation path. The project-level field `cis_fields.per_project[project].impersonable_service_accounts` counts at-risk SAs. |
| `project` | Project `role_bindings` table. |
| `storage` | GCS object secret scan (mirrors S3) + bucket `role_bindings` + optional object downloads into `loot/<bucket>/...` when `--download` is enabled on `cse gcp enumerate --service storage`. |
| `kms` | Key `role_bindings` + `key_versions` listing. |
| `secretmanager` | Secret `versions` + `role_bindings`. |
| `pubsub` | Topic `role_bindings`. |
| `cloudfunctions` | `env_vars` (regex-scanned), `secret_environment_variables`, `source_archive`, `role_bindings`. |
| `cloudrun` | Container `env_vars` + `secret_refs`, `images`, `role_bindings`. |
| `compute` | Instance `startup_script` and metadata `env_vars` (regex-scanned). |
| `gke` | `node_pools`, master `authorized_networks`, addon configuration. |
| `cloudsql` | `firewall_rules` (authorized networks), database flags as `env_vars`, `db_users`. |
| `vpc` | Per-firewall rule rendered as `firewall_rules`. |
| `bigquery` | Dataset `role_bindings` + first 50 `tables`. |
| `dns` | Resource record sets (capped at 200). |
| `cloudarmor` | Policy rules as `firewall_rules`. |
| `securitycenter` | Active `finding` resources (severity, state, resource_name, description). |
| `spanner` | Instance `role_bindings`. |

## Secret scanning

`cloud_service_enum.core.secrets` is the single regex engine reused
everywhere. It detects:

- AWS access / secret keys
- GitHub `ghp_/gho_/ghu_/ghs_/ghr_` tokens
- PEM private keys
- Slack `xoxb`/`xoxa`/`xoxp`/`xoxr`/`xoxs` tokens
- Google API keys (`AIza...`)
- Stripe live secret/restricted keys
- Generic `api_key/secret/token: <32+chars>` triples
- JWTs

`scan_text(label, content)` operates on raw strings (S3/GCS objects,
runbook code, user-data scripts, workflow definitions). `scan_mapping(label, env)`
operates on `name -> value` maps such as Lambda env-vars or App
Service settings — it both regex-matches values and flags any key
whose name contains `password`, `token`, `secret`, `api_key`, etc.

Findings are masked (`mask()` keeps the first 8 and last 4
characters) so the terminal output never echoes a full credential.
The full (still masked) finding lands in `secrets_found` on the
owning resource and rolls up into `result.cis_fields["secret_scan"]`
for bucket-style scans.

## Cost / quota notes

- Deep mode is opt-in precisely because it issues many more API
  calls per resource (typically a `get_*` or `list_*_keys` per
  resource on top of the cheap top-level `list_*`). Running
  `--deep` against an entire account can multiply the call count
  by 10–50× depending on resource density.
- Secret scanning of cloud storage (`s3` / `storage`) is the most
  expensive code path because it downloads object bodies for regex
  matching. Scan limits use `s3_scan_file_limit` (default 100 objects
  per bucket) and `s3_scan_size_limit_kb` (default 500 KB per object).
  Explicit download mode (`--download`) can pull larger sets into
  `loot/`, so scope it with `--bucket` / `--account` / `--container`
  and `--file` where possible.
- Every deep call is wrapped in a defensive `try/except`; if the
  caller lacks the additional permission (e.g. `iam:GetPolicy`,
  `secretmanager.secrets.getIamPolicy`) the resource still appears
  with its metadata fields and just omits the deep-only keys.
