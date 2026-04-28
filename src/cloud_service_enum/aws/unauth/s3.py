"""S3 bucket extraction + unauthenticated public-access probes.

Pulls bucket references out of crawled text bodies (virtual-hosted,
path-style, ``s3://`` scheme and website endpoints), then exercises the
public S3 REST API for each discovered bucket:

* Bucket existence and home region (via ``HEAD /``).
* Anonymous listing (``GET /?list-type=2``) — if allowed we capture the
  first N object keys.
* ACL / policy / website / CORS sub-resources (``GET /?acl`` etc.) —
  public responses are rare but each one is a finding worth surfacing.
* Optional per-object sampling: text-like keys get fetched (bounded) and
  run through :func:`cloud_service_enum.core.secrets.scan_text`.

Every HTTP request goes through one ``httpx.AsyncClient`` passed in by
the runner, so the caller controls timeouts and concurrency.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from importlib.resources import files
from typing import Any
from xml.etree import ElementTree as ET

import httpx

from cloud_service_enum.aws.unauth.crawler import FetchedPage
from cloud_service_enum.core.secrets import TEXT_EXTENSIONS, ext, scan_text

# ``[a-z0-9.\-]{3,63}`` matches the DNS-safe subset of AWS' bucket-naming rules.
_BUCKET_CHARS = r"[a-z0-9](?:[a-z0-9.\-]{1,61}[a-z0-9])?"

VIRTUAL_HOST_RE = re.compile(
    rf"\b({_BUCKET_CHARS})\.s3(?:[.\-]([a-z0-9\-]+))?\.amazonaws\.com\b",
    re.IGNORECASE,
)
PATH_STYLE_RE = re.compile(
    rf"\bs3(?:[.\-]([a-z0-9\-]+))?\.amazonaws\.com/({_BUCKET_CHARS})(?:/|\b)",
    re.IGNORECASE,
)
S3_SCHEME_RE = re.compile(rf"\bs3://({_BUCKET_CHARS})\b", re.IGNORECASE)
WEBSITE_RE = re.compile(
    rf"\b({_BUCKET_CHARS})\.s3-website[.\-]([a-z0-9\-]+)\.amazonaws\.com\b",
    re.IGNORECASE,
)

_RESERVED_SUBDOMAINS: frozenset[str] = frozenset(
    {
        "s3",
        "s3-external-1",
        "s3-accesspoint",
        "s3-control",
    }
)


@dataclass(frozen=True)
class BucketHit:
    """One bucket reference surfaced by crawling or direct input."""

    name: str
    region_hint: str
    first_seen_url: str


@dataclass
class BucketProbeReport:
    """Per-bucket outcome of the unauthenticated probe suite."""

    bucket: str
    region: str = ""
    existence: str = "unknown"
    public_list: bool | None = None
    public_acl: bool | None = None
    public_policy: bool | None = None
    public_website: bool | None = None
    public_cors: bool | None = None
    object_keys: list[str] = field(default_factory=list)
    summary: str = ""


def extract_buckets(pages: list[FetchedPage]) -> list[BucketHit]:
    """Scan every crawled page for bucket references, deduplicated by name."""
    hits: dict[str, BucketHit] = {}

    def _add(name: str, region: str, url: str) -> None:
        cleaned = name.strip().lower()
        if not _valid_bucket_name(cleaned):
            return
        hits.setdefault(
            cleaned,
            BucketHit(name=cleaned, region_hint=region or "", first_seen_url=url),
        )

    for page in pages:
        body = page.body or ""
        if not body:
            continue
        for match in VIRTUAL_HOST_RE.finditer(body):
            _add(match.group(1), match.group(2) or "", page.url)
        for match in PATH_STYLE_RE.finditer(body):
            _add(match.group(2), match.group(1) or "", page.url)
        for match in S3_SCHEME_RE.finditer(body):
            _add(match.group(1), "", page.url)
        for match in WEBSITE_RE.finditer(body):
            _add(match.group(1), match.group(2) or "", page.url)
    return list(hits.values())


def _valid_bucket_name(name: str) -> bool:
    if not name or name in _RESERVED_SUBDOMAINS:
        return False
    if not 3 <= len(name) <= 63:
        return False
    if name.startswith("-") or name.endswith("-") or ".." in name:
        return False
    return bool(re.fullmatch(r"[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]", name))


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------


async def probe_bucket(
    client: httpx.AsyncClient, hit: BucketHit
) -> BucketProbeReport:
    """Run the full probe suite against one bucket."""
    report = BucketProbeReport(bucket=hit.name, region=hit.region_hint)
    notes: list[str] = []

    existence, region = await _probe_existence(client, hit.name)
    report.existence = existence
    if region:
        report.region = region
    notes.append(f"HEAD: {existence}")

    if existence != "exists":
        report.summary = " · ".join(notes)
        return report

    base = _endpoint(hit.name, report.region)

    listing, keys, list_note = await _probe_list(client, base)
    report.public_list = listing
    report.object_keys = keys
    notes.append(f"list: {list_note}")

    report.public_acl, acl_note = await _probe_subresource(client, base, "acl")
    notes.append(f"acl: {acl_note}")

    report.public_policy, pol_note = await _probe_subresource(client, base, "policy")
    notes.append(f"policy: {pol_note}")

    report.public_website, web_note = await _probe_subresource(client, base, "website")
    notes.append(f"website: {web_note}")

    report.public_cors, cors_note = await _probe_subresource(client, base, "cors")
    notes.append(f"cors: {cors_note}")

    report.summary = " · ".join(notes)
    return report


async def _probe_existence(
    client: httpx.AsyncClient, bucket: str
) -> tuple[str, str]:
    """Classify the bucket via ``HEAD /``. Follows one cross-region redirect."""
    url = f"https://{bucket}.s3.amazonaws.com/"
    try:
        resp = await client.head(url)
    except httpx.HTTPError as exc:
        return (f"error: {exc.__class__.__name__}", "")
    region = resp.headers.get("x-amz-bucket-region", "") or ""
    if resp.status_code in (200, 403):
        return ("exists", region)
    if resp.status_code == 301:
        return ("exists", region or "redirect")
    if resp.status_code == 404:
        return ("no_such_bucket", region)
    if resp.status_code == 400 and "AllAccessDisabled" in (resp.text or ""):
        return ("all_access_disabled", region)
    return (f"http_{resp.status_code}", region)


async def _probe_list(
    client: httpx.AsyncClient, base: str
) -> tuple[bool | None, list[str], str]:
    """Issue ``GET /?list-type=2`` and parse keys if the bucket is public."""
    url = f"{base}/?list-type=2&max-keys=100"
    try:
        resp = await client.get(url)
    except httpx.HTTPError as exc:
        return (None, [], f"error: {exc.__class__.__name__}")
    if resp.status_code == 200:
        keys = _parse_list_keys(resp.text)
        return (True, keys, f"public ({len(keys)} keys shown)")
    if resp.status_code == 403:
        return (False, [], "denied")
    return (None, [], f"http_{resp.status_code}")


def _parse_list_keys(body: str) -> list[str]:
    if not body:
        return []
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return []
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}", 1)[0][1:]
    key_tag = f"{{{ns}}}Key" if ns else "Key"
    contents_tag = f"{{{ns}}}Contents" if ns else "Contents"
    keys: list[str] = []
    for entry in root.findall(contents_tag):
        key_node = entry.find(key_tag)
        if key_node is not None and key_node.text:
            keys.append(key_node.text)
    return keys


async def _probe_subresource(
    client: httpx.AsyncClient, base: str, subresource: str
) -> tuple[bool | None, str]:
    """Generic ``GET /?<subresource>`` probe (acl / policy / website / cors)."""
    url = f"{base}/?{subresource}"
    try:
        resp = await client.get(url)
    except httpx.HTTPError as exc:
        return (None, f"error: {exc.__class__.__name__}")
    if resp.status_code == 200:
        return (True, "public")
    if resp.status_code in (403, 405):
        return (False, "denied")
    if resp.status_code == 404:
        return (False, "not_configured")
    return (None, f"http_{resp.status_code}")


async def scan_public_objects(
    client: httpx.AsyncClient,
    bucket: str,
    region: str,
    keys: list[str],
    *,
    max_objects: int,
    max_object_size_kb: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """For text-like keys, fetch a capped slice and run the secret scanner.

    Returns ``(sampled_metadata, secret_findings)``. ``sampled_metadata``
    is one row per object actually fetched (for the ``bucket_object``
    resource kind); ``secret_findings`` is a flat list stamped with the
    owning bucket so the runner can group them.
    """
    sampled: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    if not keys:
        return sampled, findings
    base = _endpoint(bucket, region)
    byte_cap = max_object_size_kb * 1024
    headers = {"Range": f"bytes=0-{byte_cap - 1}"}
    picked = [k for k in keys if ext(k) in TEXT_EXTENSIONS][:max_objects]

    for key in picked:
        url = f"{base}/{key}"
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
        hits = scan_text(f"s3://{bucket}/{key}", body)
        sampled.append(
            {
                "bucket": bucket,
                "key": key,
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
    region: str,
    keys: list[str],
) -> list[dict[str, Any]]:
    """Download public objects and return metadata rows."""
    downloaded: list[dict[str, Any]] = []
    base = _endpoint(bucket, region)
    for key in keys:
        url = f"{base}/{key}"
        try:
            resp = await client.get(url)
        except httpx.HTTPError:
            continue
        if resp.status_code != 200:
            continue
        downloaded.append(
            {
                "bucket": bucket,
                "key": key,
                "bytes": len(resp.content),
                "content": resp.content,
            }
        )
    return downloaded


# ---------------------------------------------------------------------------
# Bruteforce helper
# ---------------------------------------------------------------------------


def bruteforce_names(
    prefixes: tuple[str, ...] | list[str],
    suffixes: list[str],
) -> list[str]:
    """Combine each prefix with each suffix in four common permutations."""
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
    """Return the bundled suffix wordlist shipped under ``data/``."""
    try:
        resource = files("cloud_service_enum.data").joinpath("s3-bucket-suffixes.txt")
        text = resource.read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        return []
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _endpoint(bucket: str, region: str) -> str:
    """Canonical virtual-hosted endpoint for ``bucket`` / ``region``."""
    if region and region not in ("redirect",):
        return f"https://{bucket}.s3.{region}.amazonaws.com"
    return f"https://{bucket}.s3.amazonaws.com"
