"""GCS bucket extraction + unauthenticated public-access probes.

Pulls ``*.storage.googleapis.com`` / ``storage.googleapis.com/<bucket>``
/ ``gs://<bucket>`` and Firebase ``*.appspot.com`` references out of
crawled text bodies, then exercises the public GCS JSON API for each
discovered (or supplied / bruteforced) candidate:

* **Metadata** — ``GET /storage/v1/b/<bucket>`` exposes
  ``projectNumber``, ``location``, ``storageClass``,
  ``iamConfiguration.uniformBucketLevelAccess``, ``website``,
  ``retentionPolicy``. This is the GCP equivalent of the "who owns this
  bucket?" attribution that's outright impossible on AWS S3.
* **Public listing** — ``GET /storage/v1/b/<bucket>/o?maxResults=100``.
* **IAM policy** — ``GET /storage/v1/b/<bucket>/iam`` surfaces the
  explicit ``allUsers`` / ``allAuthenticatedUsers`` misconfig.
* **Website** — ``GET https://<bucket>.storage.googleapis.com/``.
* **CORS** — captured from the metadata response when present.

Every HTTP call goes through one caller-supplied ``httpx.AsyncClient``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from importlib.resources import files
from typing import Any

import httpx

from cloud_service_enum.core.secrets import TEXT_EXTENSIONS, ext, scan_text
from cloud_service_enum.core.unauth.crawler import FetchedPage

_BUCKET_CHARS = r"[a-z0-9](?:[a-z0-9._\-]{1,61}[a-z0-9])?"

VIRTUAL_HOST_RE = re.compile(
    rf"\b({_BUCKET_CHARS})\.storage\.googleapis\.com\b",
    re.IGNORECASE,
)
PATH_STYLE_RE = re.compile(
    rf"\bstorage\.googleapis\.com/(?:storage/v1/b/)?({_BUCKET_CHARS})(?:/|\b)",
    re.IGNORECASE,
)
GS_SCHEME_RE = re.compile(rf"\bgs://({_BUCKET_CHARS})\b", re.IGNORECASE)
FIREBASE_RE = re.compile(rf"\b({_BUCKET_CHARS}\.appspot\.com)\b", re.IGNORECASE)

_VALID_NAME = re.compile(r"^[a-z0-9](?!.*\.\.)[a-z0-9._\-]{1,61}[a-z0-9]$")
_RESERVED_HOSTNAMES: frozenset[str] = frozenset(
    {"storage", "www", "commondatastorage", "storage-download"}
)


@dataclass(frozen=True)
class BucketHit:
    """One GCS bucket reference surfaced by crawling or direct input."""

    name: str
    first_seen_url: str


@dataclass
class BucketProbeReport:
    """Per-bucket outcome of the unauthenticated probe suite."""

    bucket: str
    existence: str = "unknown"
    project_number: str = ""
    location: str = ""
    storage_class: str = ""
    uniform_access: bool | None = None
    public_list: bool | None = None
    public_iam: bool | None = None
    iam_bindings: list[dict[str, Any]] = field(default_factory=list)
    website: bool | None = None
    website_main_page: str = ""
    cors_wildcard: bool | None = None
    cors_credentials: bool | None = None
    object_names: list[str] = field(default_factory=list)
    summary: str = ""


def extract_buckets(pages: list[FetchedPage]) -> list[BucketHit]:
    """Deduplicated GCS bucket references across every page body."""
    hits: dict[str, BucketHit] = {}

    def _add(name: str, url: str) -> None:
        cleaned = name.strip().lower()
        if not _valid_bucket_name(cleaned):
            return
        hits.setdefault(cleaned, BucketHit(name=cleaned, first_seen_url=url))

    for page in pages:
        body = page.body or ""
        if not body:
            continue
        for match in VIRTUAL_HOST_RE.finditer(body):
            _add(match.group(1), page.url)
        for match in PATH_STYLE_RE.finditer(body):
            _add(match.group(1), page.url)
        for match in GS_SCHEME_RE.finditer(body):
            _add(match.group(1), page.url)
        for match in FIREBASE_RE.finditer(body):
            _add(match.group(1), page.url)
    return list(hits.values())


def _valid_bucket_name(name: str) -> bool:
    if not name or name in _RESERVED_HOSTNAMES:
        return False
    if not 3 <= len(name) <= 63:
        return False
    if name.startswith("-") or name.endswith("-"):
        return False
    if name.startswith(".") or name.endswith("."):
        return False
    if ".." in name:
        return False
    return bool(_VALID_NAME.match(name))


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------


_GCS_BASE = "https://storage.googleapis.com/storage/v1/b"


async def probe_bucket(
    client: httpx.AsyncClient, hit: BucketHit
) -> BucketProbeReport:
    """Run the full probe suite against one bucket."""
    report = BucketProbeReport(bucket=hit.name)
    notes: list[str] = []

    existence, meta = await _probe_metadata(client, hit.name)
    report.existence = existence
    notes.append(f"metadata: {existence}")
    if meta:
        report.project_number = str(meta.get("projectNumber") or "")
        report.location = str(meta.get("location") or "")
        report.storage_class = str(meta.get("storageClass") or "")
        iam_cfg = (meta.get("iamConfiguration") or {})
        ubla = (iam_cfg.get("uniformBucketLevelAccess") or {}).get("enabled")
        report.uniform_access = bool(ubla) if ubla is not None else None
        website = meta.get("website")
        if isinstance(website, dict) and website.get("mainPageSuffix"):
            report.website_main_page = str(website.get("mainPageSuffix"))
        cors = meta.get("cors") or []
        if isinstance(cors, list) and cors:
            origins = set()
            for rule in cors:
                if isinstance(rule, dict):
                    for origin in rule.get("origin") or []:
                        origins.add(origin)
            if "*" in origins:
                report.cors_wildcard = True

    if existence != "exists":
        report.summary = " · ".join(notes)
        return report

    listing, names, list_note = await _probe_list(client, hit.name)
    report.public_list = listing
    report.object_names = names
    notes.append(f"list: {list_note}")

    public_iam, bindings, iam_note = await _probe_iam(client, hit.name)
    report.public_iam = public_iam
    report.iam_bindings = bindings
    notes.append(f"iam: {iam_note}")

    website_ok, web_note = await _probe_website(client, hit.name)
    report.website = website_ok
    notes.append(f"website: {web_note}")

    report.summary = " · ".join(notes)
    return report


async def _probe_metadata(
    client: httpx.AsyncClient, bucket: str
) -> tuple[str, dict[str, Any] | None]:
    """``GET /storage/v1/b/<bucket>`` — 200 leaks full metadata."""
    url = f"{_GCS_BASE}/{bucket}"
    try:
        resp = await client.get(url)
    except httpx.HTTPError as exc:
        return (f"error: {exc.__class__.__name__}", None)
    if resp.status_code == 200:
        try:
            return ("exists", resp.json())
        except ValueError:
            return ("exists", None)
    if resp.status_code in (401, 403):
        # Bucket definitely exists, but metadata is locked down.
        return ("exists", None)
    if resp.status_code == 404:
        return ("no_such_bucket", None)
    return (f"http_{resp.status_code}", None)


async def _probe_list(
    client: httpx.AsyncClient, bucket: str
) -> tuple[bool | None, list[str], str]:
    """``GET /o?maxResults=100`` — 200 means anonymous listing is allowed."""
    url = f"{_GCS_BASE}/{bucket}/o?maxResults=100"
    try:
        resp = await client.get(url)
    except httpx.HTTPError as exc:
        return (None, [], f"error: {exc.__class__.__name__}")
    if resp.status_code == 200:
        try:
            payload = resp.json()
        except ValueError:
            return (True, [], "public (unparseable body)")
        items = payload.get("items") or []
        names: list[str] = []
        for item in items:
            if isinstance(item, dict) and item.get("name"):
                names.append(str(item["name"]))
        return (True, names, f"public ({len(names)} objects shown)")
    if resp.status_code in (401, 403):
        return (False, [], "denied")
    return (None, [], f"http_{resp.status_code}")


async def _probe_iam(
    client: httpx.AsyncClient, bucket: str
) -> tuple[bool | None, list[dict[str, Any]], str]:
    """``GET /iam`` — 200 surfaces explicit ``allUsers`` misconfigs."""
    url = f"{_GCS_BASE}/{bucket}/iam"
    try:
        resp = await client.get(url)
    except httpx.HTTPError as exc:
        return (None, [], f"error: {exc.__class__.__name__}")
    if resp.status_code == 200:
        try:
            payload = resp.json()
        except ValueError:
            return (False, [], "public (unparseable body)")
        bindings_raw = payload.get("bindings") or []
        bindings: list[dict[str, Any]] = []
        public = False
        for b in bindings_raw:
            if not isinstance(b, dict):
                continue
            members = b.get("members") or []
            if any(
                m in ("allUsers", "allAuthenticatedUsers")
                for m in members
            ):
                public = True
            bindings.append(
                {
                    "role": b.get("role"),
                    "members": members,
                }
            )
        return (public, bindings, "public bindings" if public else "public (no allUsers)")
    if resp.status_code in (401, 403):
        return (False, [], "denied")
    return (None, [], f"http_{resp.status_code}")


async def _probe_website(
    client: httpx.AsyncClient, bucket: str
) -> tuple[bool | None, str]:
    """Hit the virtual-hosted URL to see if the bucket is fronting a site."""
    url = f"https://{bucket}.storage.googleapis.com/"
    try:
        resp = await client.get(url)
    except httpx.HTTPError as exc:
        return (None, f"error: {exc.__class__.__name__}")
    if resp.status_code in (200, 301, 302):
        return (True, f"HTTP {resp.status_code}")
    if resp.status_code in (401, 403, 404):
        return (False, f"HTTP {resp.status_code}")
    return (None, f"http_{resp.status_code}")


async def scan_public_objects(
    client: httpx.AsyncClient,
    bucket: str,
    names: list[str],
    *,
    max_objects: int,
    max_object_size_kb: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """For text-like objects, fetch a capped slice and run the secret scanner."""
    sampled: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    if not names:
        return sampled, findings
    byte_cap = max_object_size_kb * 1024
    headers = {"Range": f"bytes=0-{byte_cap - 1}"}
    picked = [n for n in names if ext(n) in TEXT_EXTENSIONS][:max_objects]

    for name in picked:
        # Path-style URL (the virtual-hosted form URL-encodes oddly for
        # names with ``/``; the path style works for every valid name).
        url = f"https://storage.googleapis.com/{bucket}/{name}"
        try:
            resp = await client.get(url, headers=headers)
        except httpx.HTTPError:
            continue
        if resp.status_code not in (200, 206):
            continue
        raw = resp.content
        if len(raw) > byte_cap:
            raw = raw[:byte_cap]
        try:
            body = raw.decode(resp.encoding or "utf-8", errors="replace")
        except (LookupError, ValueError):
            body = raw.decode("utf-8", errors="replace")
        hits = scan_text(f"gs://{bucket}/{name}", body)
        sampled.append(
            {
                "bucket": bucket,
                "key": name,
                "size": len(resp.content),
                "bytes_scanned": len(raw),
                "secret_count": len(hits),
            }
        )
        for hit in hits:
            row = hit.as_dict()
            row["bucket"] = bucket
            findings.append(row)
    return sampled, findings


async def download_public_objects(
    client: httpx.AsyncClient,
    bucket: str,
    names: list[str],
) -> list[dict[str, Any]]:
    """Download public GCS objects and return metadata rows."""
    downloaded: list[dict[str, Any]] = []
    for name in names:
        url = f"https://storage.googleapis.com/{bucket}/{name}"
        try:
            resp = await client.get(url)
        except httpx.HTTPError:
            continue
        if resp.status_code != 200:
            continue
        downloaded.append(
            {
                "bucket": bucket,
                "key": name,
                "bytes": len(resp.content),
                "content": resp.content,
            }
        )
    return downloaded


# ---------------------------------------------------------------------------
# Bruteforce helpers
# ---------------------------------------------------------------------------


def bruteforce_names(
    prefixes: tuple[str, ...] | list[str],
    suffixes: list[str],
) -> list[str]:
    """GCS permits ``_``, so we emit one more permutation than S3.

    Each valid ``(prefix, suffix)`` pair yields ``<p>-<s>``, ``<p>.<s>``,
    ``<p><s>``, ``<p>_<s>``, and ``<s>-<p>``.
    """
    if not prefixes or not suffixes:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for raw_prefix in prefixes:
        prefix = raw_prefix.strip().lower()
        if not prefix:
            continue
        candidates: list[str] = [prefix]
        for raw_suffix in suffixes:
            suffix = raw_suffix.strip().lower()
            if not suffix:
                continue
            candidates.extend(
                [
                    f"{prefix}-{suffix}",
                    f"{prefix}.{suffix}",
                    f"{prefix}{suffix}",
                    f"{prefix}_{suffix}",
                    f"{suffix}-{prefix}",
                ]
            )
        for name in candidates:
            if name in seen:
                continue
            if not _valid_bucket_name(name):
                continue
            seen.add(name)
            out.append(name)
    return out


def load_default_suffix_wordlist() -> list[str]:
    """Bundled suffix list shipped under ``cloud_service_enum/data/``."""
    try:
        resource = files("cloud_service_enum.data").joinpath("gcs-bucket-suffixes.txt")
        text = resource.read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        return []
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
