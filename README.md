<pre>
                                    .  *  .   .       .
       _________________     *  .       .    *      .  *
      /                 \      .   .  ___       .       *
     /     /\      /\    \  .       _/   \_   .      .
    /     /  \____/  \    \    .   /       \    *  .
    \    /            \   /        \_     _/   .
     \  /     C S E    \ /     .     \___/        *  .
      \/________________/    .                .
        cloud-service-enum         AWS · Azure · GCP · OSINT
        ─────────────────────────────────────────────────────
        async-native  ·  read-only  ·  one binary, three clouds
</pre>

> **Find every resource. Read every policy. Scan every secret.
> All from one CLI, in under a minute.**

`cloud-service-enum` (`cse`) is a multi-cloud enumeration tool for
security engineers, pentesters, and platform teams who need a
faithful picture of what's actually running in their cloud accounts
and who can touch it. Point it at credentials, hit enter, watch the
estate appear.

It is a **discovery** tool, not a scanner. `cse` never modifies a
resource, never opens an inbound connection, never makes a pass/fail
judgement. It just reads, organises, and prints — extremely fast.

```text
[ AWS ]   34 services   ▸  parallel walk across every region
[ Azure ] 33 services   ▸  ARM + Microsoft Graph in one run
[ GCP ]   24 services   ▸  with service-account impersonation map
[ OSINT ] 1 module      ▸  no creds required
```

---

## What it actually does

For each provider, `cse` ships a registry of small, focused enumerators
(34 for AWS, 33 for Azure, 24 for GCP, plus an OSINT module). Every
enumerator is fully async and runs concurrently inside a single
`asyncio` event loop, so a full account walk that would take a CLI
script five minutes typically completes in under thirty seconds.

Out of the box, a single command will:

- **Inventory the estate** — every region, every subscription, every
  project, every visible resource — with the metadata most useful for
  triage (resource id, name, region, encryption flags, public-access
  flags, network exposure, attached identity, owner).
- **Map identity and access** — IAM users, roles, custom roles, group
  memberships, RBAC assignments, service-account impersonation paths,
  Conditional Access policies, MFA registration state, key ages.
- **Pull policy bodies on demand** — when you focus on a single
  service, `cse` automatically deep-scans it: full IAM and resource
  policies, KMS key policies, S3/GCS bucket policies, SCPs, WAF rule
  sets, NSG / security group / firewall rules, all printed as readable
  JSON or tables in the terminal.
- **Surface attacker-relevant payloads** — Lambda env-vars, EC2
  user-data, Azure runbook scripts, Logic App and Step Function
  definitions, Cloud Function source archives, Container App env
  blocks, App Service connection strings — anything an attacker would
  pivot through after a foothold.
- **Hunt secrets in plain text** — every text surface the deep-scan
  layer fetches is regex-matched for AWS keys, GitHub tokens, Slack
  tokens, Google API keys, Stripe keys, PEM private keys, JWTs, and
  generic `api_key=…`-style triples. S3 and GCS object scanning is
  available as an opt-in pass over file contents.
- **Pull Microsoft Graph data** — MFA registration, Conditional
  Access, group ownership, app registrations — with the Graph SDK,
  not screen-scraping.
- **Run lightweight OSINT on a domain** — async subdomain brute-force,
  DNS record enumeration, and cloud-provider attribution from a single
  domain name, no credentials required.

Every run produces one canonical `EnumerationRun` document. The
terminal view, the JSON report, the spreadsheet — all serialise the
exact same structure (described in
[`docs/result-schema.md`](docs/result-schema.md)), so anything you can
see on screen you can also grep, diff, or pipe into another tool.

## A taste of the output

A focused IAM walk on AWS looks something like this:

```text
$ cse aws enumerate --profile auditor --service iam

╭──────────────────── auth ────────────────────╮  ╭───────── scope ─────────╮
│  account   111111111111                      │  │  regions    us-east-1   │
│  arn       arn:aws:iam::111111111111:        │  │  services   iam         │
│            user/auditor                      │  │  deep       on (focus)  │
│  method    profile (auditor)                 │  │  secret     on (auto)   │
╰──────────────────────────────────────────────╯  ╰─────────────────────────╯

▸ aws · iam · 14 resources · 0.42s
  ┏━━━━━━━━━━━━┯━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
  ┃ kind       │ name / arn                                                ┃
  ┡━━━━━━━━━━━━┿━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
  │ user       │ arn:aws:iam::111111111111:user/dev-bot     mfa=off keys=2 │
  │ role       │ arn:aws:iam::111111111111:role/Admin       trust=*        │
  │ policy     │ arn:aws:iam::111111111111:policy/S3Full    attached=12    │
  └────────────┴───────────────────────────────────────────────────────────┘

  ╭─ policy_document · S3Full ────────────────────────────────────────────╮
  │ {                                                                     │
  │   "Version": "2012-10-17",                                            │
  │   "Statement": [{ "Effect": "Allow", "Action": "s3:*", "Resource": …  │
  │ }                                                                     │
  ╰───────────────────────────────────────────────────────────────────────╯

✓ Wrote reports/aws-20260422-120145.json
```

(Yes, dangerous roles get coloured red. Yes, secrets get masked.)

## Why this and not the other thing

- **Async-native everywhere.** `aioboto3` for AWS, `azure-*.aio` and
  `msgraph-sdk` for Azure, `google-cloud-*` (wrapped in
  `asyncio.to_thread` where the SDK is sync-only) for GCP. One event
  loop, `TaskGroup`-based fan-out, bounded by per-provider semaphores.
  No thread-pool pyramids.
- **No fragile orchestration glue.** Each service is a ~100 line class
  with a single `collect` coroutine. Adding a new one is mechanical;
  reading the source for a service you care about is a five-minute job.
- **Sensible defaults, no surprise bills.** A vanilla
  `cse aws enumerate` is cheap and read-only. Deep payloads (extra API
  calls per resource) and object-body downloads are opt-in, or
  auto-enabled only when you explicitly focus on a single service.
- **Doesn't crash on a missing permission.** Every call is wrapped in
  a defensive `try/except`. If the caller can't read one resource
  type, that one row notes the failure and the rest of the run keeps
  going.
- **Output you can actually read.** Rich tables, panels, syntax-
  highlighted JSON, role-binding tables that highlight dangerous roles
  in red, and an auth panel up top so you always know which identity
  produced the data in front of you.

```
╔══════════════════════════════════════════════════════════════════╗
║   Setup ▸ Install ▸ Authenticate ▸ Enumerate ▸ Read the report   ║
╚══════════════════════════════════════════════════════════════════╝
```

## Requirements

| Component | Minimum | Notes |
|-----------|---------|-------|
| Python | 3.12 | 3.13 and 3.14 (incl. free-threaded `3.14t`) also supported |
| pip | 24.0 | older pip cannot resolve some optional extras cleanly |
| OS | macOS, Linux, Windows | tested on macOS and Linux |

Optional system tooling:

- **AWS CLI v2** — only needed if you authenticate via named profiles or SSO
- **Azure CLI** — only needed if you use `--use-cli`
- **gcloud CLI** — only needed if you authenticate via Application Default Credentials

## Installation

> The package is not on PyPI yet, so installs go through a local clone
> + `pip install -e` (editable) or `pip install .` (regular).

### Recommended: full install in a virtual environment

```bash
git clone https://github.com/h3llo0p3rator/cloud-service-enum.git
cd cloud-service-enum

python3.14 -m venv .venv
source .venv/bin/activate            # PowerShell: .venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
pip install -e ".[all]"

cse --version
cse --help
```

### Lean install: only the providers you need

Each provider extra pulls in just the SDKs that provider actually
uses, so you can install the subset relevant to your environment:

```bash
pip install -e ".[aws]"         # aioboto3
pip install -e ".[azure]"       # azure-* + msgraph-sdk
pip install -e ".[gcp]"         # google-cloud-* + google-auth
pip install -e ".[osint]"       # dnspython, python-whois
pip install -e ".[reports]"     # openpyxl, python-docx, fpdf2, lxml
pip install -e ".[all]"         # everything above
```

Multiple extras combine: `pip install -e ".[aws,reports]"`.

### Pre-built wheel

```bash
pip install build
python -m build           # emits dist/*.whl and dist/*.tar.gz
pip install ./dist/cloud_service_enum-2.0.0-py3-none-any.whl[all]
```

Or, for an isolated CLI install via `pipx`:

```bash
pipx install "./dist/cloud_service_enum-2.0.0-py3-none-any.whl[all]"
```

## Configuration

`cse` reads no config file — every parameter is a CLI flag or an
environment variable. The variables below are the standard ones each
cloud SDK already honours, so existing setups work without changes.

### AWS

```bash
export AWS_PROFILE="my-profile"          # or AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY
export AWS_DEFAULT_REGION="us-east-1"
```

### Azure

```bash
export AZURE_TENANT_ID="..."
export AZURE_CLIENT_ID="..."
export AZURE_CLIENT_SECRET="..."         # or AZURE_CLIENT_CERTIFICATE_PATH
export AZURE_SUBSCRIPTION_ID="..."        # optional, scoping
```

### GCP

```bash
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/sa.json"
export GOOGLE_CLOUD_PROJECT="my-project"
```

A starter `.env.example` is included; copy it and edit:

```bash
cp .env.example .env
```

## Driving it

Every command follows the same shape:

```text
cse <provider> <command> [options]
       │           │
       │           └──  enumerate · services · mfa (azure) · …
       └──  aws · azure · gcp · osint
```

### AWS

```bash
# Enumerate every region the caller can see
cse aws enumerate --profile my-profile

# Subset of services across two regions.
# Focusing on a service automatically enables its deep scan + secret scan.
cse aws enumerate \
  --profile my-profile \
  --service s3 --service iam \
  --regions us-east-1,eu-west-1

# Force every service into deep mode without secret scanning
cse aws enumerate --profile my-profile --deep --no-secret-scan

# Disable the auto-enabled secret scan when focusing on s3
cse aws enumerate --profile my-profile --service s3 --no-secret-scan

# Assume a role + emit JSON and XLSX reports
cse aws enumerate \
  --profile my-profile \
  --role-arn arn:aws:iam::111111111111:role/auditor \
  --external-id abc \
  --report-format json --report-format xlsx
```

#### Unauthenticated recon

A lot of AWS services leak attacker-useful identifiers through the
client-side bundles of their consuming web apps. The `aws unauth`
sub-tree wraps recon flows for those leaks — no AWS credentials
required. Three commands are wired up today: `cognito`, `s3`, and
`api-gateway`. They share the same crawler and credential regex sweep,
so you can point them at the same `--url` and the results will line up.

```bash
# Crawl a web app, pull userPoolIds / identityPoolIds / appClientIds
# from its JS bundles, then fingerprint each pool via the public
# Cognito API (read-only probes, on by default).
cse aws unauth cognito --url https://app.example.com

# Add the opt-in SignUp probe to detect self-registration
# (no user is actually created).
cse aws unauth cognito --url https://app.example.com --probe-signup

# Probe an explicit bucket + whatever the crawler finds at the target URL.
cse aws unauth s3 --url https://app.example.com --bucket acme-assets

# Add a small wordlist bruteforce pass using two prefixes.
cse aws unauth s3 --bruteforce \
  --bruteforce-prefix acme --bruteforce-prefix acme-prod

# Fingerprint every API Gateway / Lambda Function URL the web app references.
cse aws unauth api-gateway --url https://app.example.com
```

The same `unauth` shape is also wired up for Azure and GCP:

```bash
# Azure: crawl for *.core.windows.net accounts, probe every storage
# surface (blob/file/queue/table/dfs) + common blob containers, and
# secret-scan any public blobs.
cse azure unauth storage --url https://app.example.com

# Azure: wordlist bruteforce for storage-account names.
cse azure unauth storage --bruteforce \
  --bruteforce-prefix acme --bruteforce-prefix acmeprod

# GCP: crawl for *.storage.googleapis.com buckets, probe metadata /
# listing / IAM (metadata leaks projectNumber), secret-scan public
# objects.
cse gcp unauth bucket --url https://app.example.com

# GCP: wordlist bruteforce for bucket names.
cse gcp unauth bucket --bruteforce \
  --bruteforce-prefix acme --bruteforce-prefix acme-prod
```

Full reference: [`docs/unauth-scans.md`](docs/unauth-scans.md).

### Azure

```bash
# Full enumeration of one subscription using a service principal
cse azure enumerate \
  --tenant-id $AZURE_TENANT_ID \
  --client-id $AZURE_CLIENT_ID \
  --client-secret $AZURE_CLIENT_SECRET \
  --subscription $AZURE_SUBSCRIPTION_ID

# Microsoft Graph MFA status across every user
cse azure mfa \
  --tenant-id $AZURE_TENANT_ID \
  --client-id $AZURE_CLIENT_ID \
  --client-secret $AZURE_CLIENT_SECRET \
  --report-format xlsx
```

### GCP

```bash
# Project is auto-detected from the service-account JSON if you omit --project
cse gcp enumerate --service-account-file ./sa.json

# Focused IAM walk: dumps service-account impersonation paths and custom roles
cse gcp enumerate --service-account-file ./sa.json --service iam
```

### OSINT

```bash
cse osint example.com --report-format json --report-format csv
```

## Authentication

| Provider | Methods supported |
|----------|-------------------|
| AWS | named profile, static keys + optional session token, assumed role (with MFA / ExternalId / web-identity federation), default credential chain |
| Azure | client secret, certificate, username + password, workload identity federation, managed identity, `az login`, default chain |
| GCP | service-account file, inline SA JSON, access token, impersonation, workload identity federation, application default credentials |

## Output

Every run produces one `EnumerationRun` document, fully described in
[`docs/result-schema.md`](docs/result-schema.md). Reports are just
serialisations of that document — JSON preserves full fidelity,
XLSX / DOCX / PDF are convenience views.

Reports land in `./reports/` by default — change with `--output-dir`.

The terminal output is the primary view, with:

- An **authentication panel** showing which identity, tenant,
  subscription, project, or assumed role produced the data.
- A **configuration panel** summarising the run scope (regions,
  services, deep / secret-scan flags).
- **Per-service tables** grouped by resource kind.
- **Detail panels** under each resource for deep-scan payloads:
  policy JSON, masked env-var maps, syntax-highlighted definitions
  and scripts, firewall rule tables, IAM role bindings (dangerous
  roles in red), secret findings, and S3 / GCS scan stats.

See [`docs/deep-scans.md`](docs/deep-scans.md) for the full per-service
field list, including which extra fields each enumerator pulls in deep
mode and how secret scanning works.

## Service coverage

Want the canonical list?

```bash
cse aws services
cse azure services
cse gcp services
```

## Project layout

```
src/cloud_service_enum/
├── core/          # models, registry, runner, concurrency, display, secrets
├── aws/           # AwsAuthenticator + 34 service enumerators
├── azure/         # AzureAuthenticator + 33 service enumerators
├── gcp/           # GcpAuthenticator + 24 service enumerators
├── osint/         # async subdomain + DNS + provider attribution
├── reporting/     # JSON / CSV / XLSX / XML / DOCX / PDF writers
├── clis/          # Click sub-commands per provider
└── data/          # bundled wordlists and reference data
```

## License

MIT — see [LICENSE](LICENSE). Use it, fork it, ship it. Don't
enumerate things you don't have permission to enumerate.
