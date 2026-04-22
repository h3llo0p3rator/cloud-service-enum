"""Azure Storage account / container extraction + unauthenticated probes.

Pulls ``*.<surface>.core.windows.net`` and ``*.z<n>.web.core.windows.net``
references out of crawled text bodies, classifies them into account /
container / static-website hits, then exercises the public REST
endpoints for each discovered (or supplied / bruteforced) candidate:

* **Account-level existence** across all five storage services — blob,
  file, queue, table, dfs — plus static-website hosts.
* **Container listing** (``?restype=container&comp=list``) — a public
  listing is the direct misconfig signal; we capture the first N blob
  names and flag the ``x-ms-blob-public-access`` header.
* **Container metadata / ACL** for soft-existence signals when listing
  is denied.
* **File-share listing** (``?restype=share&comp=list``) for any
  user-supplied share names.
* **Blob sampling** — text-like blobs from public containers are
  fetched (``Range``-capped) and run through
  :func:`cloud_service_enum.core.secrets.scan_text`.
* **SAS token extraction** — any ``sv=…&sig=…`` query string found in a
  crawled body is surfaced; an accidentally-leaked SAS is effectively a
  credential.

Every HTTP request flows through one caller-supplied
``httpx.AsyncClient`` so the runner governs timeouts and concurrency.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from importlib.resources import files
from typing import Any
from xml.etree import ElementTree as ET

import httpx

from cloud_service_enum.core.secrets import TEXT_EXTENSIONS, ext, scan_text
from cloud_service_enum.core.unauth.crawler import FetchedPage

ACCOUNT_RE = re.compile(
    r"\b([a-z0-9]{3,24})\.(blob|file|queue|table|dfs)\.core\.windows\.net\b",
    re.IGNORECASE,
)
WEBSITE_RE = re.compile(
    r"\b([a-z0-9]{3,24})\.z\d+\.web\.core\.windows\.net\b",
    re.IGNORECASE,
)
# ``<account>.blob.core.windows.net/<container>[/...]``
CONTAINER_PATH_RE = re.compile(
    r"\b([a-z0-9]{3,24})\.blob\.core\.windows\.net/"
    r"([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])(?:/|\b)",
    re.IGNORECASE,
)
SAS_RE = re.compile(
    r"[?&]sv=\d{4}-\d{2}-\d{2}(?:&[^\s\"'<>]*?)?&sig=[A-Za-z0-9%/+=\-_]{20,}",
    re.IGNORECASE,
)

# Static-website endpoints are stamped with a region-specific ``z<n>``
# subdomain (``z1``..``z36`` at the time of writing). We probe a curated
# set covering every public cloud region rather than all of them; these
# are the common ones at ~second-look coverage.
STATIC_WEBSITE_ZONES: tuple[str, ...] = (
    "z1", "z2", "z3", "z4", "z5", "z6", "z7", "z8", "z9",
    "z13", "z14", "z16", "z20", "z21", "z22", "z23", "z26",
    "z29", "z33", "z36",
)

_VALID_ACCOUNT = re.compile(r"^[a-z0-9]{3,24}$")
_VALID_CONTAINER = re.compile(r"^[a-z0-9](?!.*--)[a-z0-9\-]{1,61}[a-z0-9]$")
# Built-in container wordlist (small, curated; ``$web`` gets URL-encoded
# when probed since ``$`` is a literal character in container names).
DEFAULT_CONTAINER_WORDLIST: tuple[str, ...] = (
    "backup", "backups", "logs", "prod", "dev", "staging", "public",
    "private", "uploads", "media", "assets", "config", "configs",
    "secrets", "terraform", "terraform-state", "tfstate", "artifacts",
    "archive", "archives", "web", "$web", "data", "reports", "images",
)


@dataclass
class AccountHit:
    """One storage-account reference surfaced by crawling or direct input."""

    name: str
    surfaces: set[str] = field(default_factory=set)
    first_seen_url: str = ""


@dataclass(frozen=True)
class ContainerHit:
    """One ``(account, container)`` pair surfaced by crawling or direct input."""

    account: str
    container: str
    first_seen_url: str


@dataclass
class StorageProbeReport:
    """Per-account outcome of the unauthenticated probe suite.

    ``existence`` mirrors the S3 report: ``"exists"`` is the only value
    the runner renders; everything else is treated as noise.
    """

    account: str
    existence: str = "unknown"
    surfaces_live: list[str] = field(default_factory=list)
    blob_list_public: bool | None = None
    file_list_public: bool | None = None
    queue_list_public: bool | None = None
    table_exists: bool | None = None
    dfs_exists: bool | None = None
    static_website: str = ""  # populated with a URL if one responds
    summary: str = ""


@dataclass
class ContainerProbeReport:
    """Per-container outcome for listing / ACL / metadata probes."""

    account: str
    container: str
    public_list: bool | None = None
    public_access_level: str = ""  # "blob" | "container" | "none" | ""
    metadata_200: bool | None = None
    blob_keys: list[str] = field(default_factory=list)
    summary: str = ""


def extract_accounts(pages: list[FetchedPage]) -> list[AccountHit]:
    """Return one :class:`AccountHit` per unique account seen across pages."""
    hits: dict[str, AccountHit] = {}

    def _touch(name: str, surface: str, url: str) -> None:
        cleaned = name.strip().lower()
        if not _VALID_ACCOUNT.match(cleaned):
            return
        hit = hits.setdefault(
            cleaned,
            AccountHit(name=cleaned, first_seen_url=url),
        )
        hit.surfaces.add(surface)

    for page in pages:
        body = page.body or ""
        if not body:
            continue
        for match in ACCOUNT_RE.finditer(body):
            _touch(match.group(1), match.group(2).lower(), page.url)
        for match in WEBSITE_RE.finditer(body):
            _touch(match.group(1), "web", page.url)
    return list(hits.values())


def extract_containers(pages: list[FetchedPage]) -> list[ContainerHit]:
    """Return ``(account, container)`` pairs seen across crawled bodies."""
    seen: set[tuple[str, str]] = set()
    out: list[ContainerHit] = []
    for page in pages:
        body = page.body or ""
        if not body:
            continue
        for match in CONTAINER_PATH_RE.finditer(body):
            account = match.group(1).lower()
            container = match.group(2).lower()
            if not _VALID_ACCOUNT.match(account):
                continue
            if not _VALID_CONTAINER.match(container):
                continue
            key = (account, container)
            if key in seen:
                continue
            seen.add(key)
            out.append(
                ContainerHit(account=account, container=container, first_seen_url=page.url)
            )
    return out


def extract_sas_tokens(pages: list[FetchedPage]) -> list[dict[str, Any]]:
    """Surface every SAS token found during the crawl as a credential hit."""
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for page in pages:
        body = page.body or ""
        if not body:
            continue
        for match in SAS_RE.finditer(body):
            token = match.group(0)
            if token in seen:
                continue
            seen.add(token)
            findings.append(
                {
                    "type": "azure-sas-token",
                    "source": page.url,
                    "match": _mask_sas(token),
                    "length": len(token),
                }
            )
    return findings


def _mask_sas(token: str) -> str:
    """Redact the signature portion of a SAS before display / reporting."""
    match = re.search(r"sig=([A-Za-z0-9%/+=\-_]{20,})", token)
    if not match:
        return token
    sig = match.group(1)
    keep = sig[:6]
    return token.replace(sig, f"{keep}…(redacted {len(sig)} chars)")


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------


async def probe_account(
    client: httpx.AsyncClient, account: str
) -> StorageProbeReport:
    """Hit every surface for ``account`` and consolidate into one report.

    Each of the five service endpoints is probed with the cheapest call
    that reveals existence:

    * blob / file / queue — ``GET /?comp=list`` (200 = public listing;
      400/403 = account exists but anonymous listing denied).
    * table — ``GET /Tables`` (400 ``InvalidAuthenticationInfo`` = exists).
    * dfs — ``GET /?resource=account`` (same signal shape as blob).
    """
    report = StorageProbeReport(account=account)
    notes: list[str] = []
    surfaces_live: list[str] = []

    blob_status, blob_public = await _probe_list_endpoint(
        client, f"https://{account}.blob.core.windows.net/?comp=list"
    )
    if blob_status == "exists":
        surfaces_live.append("blob")
        report.blob_list_public = blob_public
    notes.append(f"blob: {blob_status}")

    file_status, file_public = await _probe_list_endpoint(
        client, f"https://{account}.file.core.windows.net/?comp=list"
    )
    if file_status == "exists":
        surfaces_live.append("file")
        report.file_list_public = file_public
    notes.append(f"file: {file_status}")

    queue_status, queue_public = await _probe_list_endpoint(
        client, f"https://{account}.queue.core.windows.net/?comp=list"
    )
    if queue_status == "exists":
        surfaces_live.append("queue")
        report.queue_list_public = queue_public
    notes.append(f"queue: {queue_status}")

    table_status = await _probe_table(
        client, f"https://{account}.table.core.windows.net/Tables"
    )
    if table_status == "exists":
        surfaces_live.append("table")
        report.table_exists = True
    notes.append(f"table: {table_status}")

    dfs_status, _ = await _probe_list_endpoint(
        client, f"https://{account}.dfs.core.windows.net/?resource=account"
    )
    if dfs_status == "exists":
        surfaces_live.append("dfs")
        report.dfs_exists = True
    notes.append(f"dfs: {dfs_status}")

    website = await _probe_static_website(client, account)
    if website:
        surfaces_live.append("web")
        report.static_website = website
        notes.append(f"web: {website}")
    else:
        notes.append("web: disabled")

    report.surfaces_live = surfaces_live
    report.existence = "exists" if surfaces_live else "no_such_account"
    report.summary = " · ".join(notes)
    return report


async def _probe_list_endpoint(
    client: httpx.AsyncClient, url: str
) -> tuple[str, bool | None]:
    """Classify a ``?comp=list`` style endpoint.

    Returns ``(status, public_bool_or_None)``:

    * ``status`` ∈ ``{"exists", "no_such_account", "error: …"}``.
    * ``public`` — ``True`` if the 200 body actually lists containers /
      blobs / queues, ``False`` if the service responded with a normal
      auth error, ``None`` when we can't tell.
    """
    try:
        resp = await client.get(url)
    except httpx.HTTPError as exc:
        return (f"error: {exc.__class__.__name__}", None)

    if resp.status_code == 200 and "<EnumerationResults" in (resp.text or ""):
        return ("exists", True)
    # 400 / 403 / 409 with the Azure server banner all mean "service is
    # up but anonymous listing is off" — the account definitely exists.
    if resp.status_code in (400, 403, 404, 409) and _is_azure_service(resp):
        # 404 is ambiguous — DNS resolved and TLS handshook, but the
        # body says "ResourceNotFound". That's still an authoritative
        # response from an existing storage service.
        return ("exists", False)
    if resp.status_code in (404,) and not _is_azure_service(resp):
        return ("no_such_account", None)
    return (f"http_{resp.status_code}", None)


async def _probe_table(client: httpx.AsyncClient, url: str) -> str:
    """Table service has no ``?comp=list`` — ``/Tables`` is the cheapest call."""
    try:
        resp = await client.get(url)
    except httpx.HTTPError as exc:
        return f"error: {exc.__class__.__name__}"
    if resp.status_code in (200, 400, 401, 403) and _is_azure_service(resp):
        return "exists"
    if resp.status_code == 404 and not _is_azure_service(resp):
        return "no_such_account"
    return f"http_{resp.status_code}"


async def _probe_static_website(
    client: httpx.AsyncClient, account: str
) -> str:
    """Probe a handful of ``z<n>`` static-website zones with a cheap HEAD."""
    for zone in STATIC_WEBSITE_ZONES:
        url = f"https://{account}.{zone}.web.core.windows.net/"
        try:
            resp = await client.head(url)
        except httpx.HTTPError:
            continue
        if resp.status_code in (200, 301, 302, 404) and _is_azure_service(resp):
            return url
    return ""


def _is_azure_service(resp: httpx.Response) -> bool:
    """Cheap fingerprint: Azure storage stamps a recognisable ``Server`` header."""
    server = (resp.headers.get("server") or "").lower()
    return (
        "windows-azure" in server
        or "azureblob" in server.replace("-", "")
        or "microsoft-httpapi" in server
        or resp.headers.get("x-ms-request-id") is not None
    )


async def probe_container(
    client: httpx.AsyncClient,
    account: str,
    container: str,
) -> ContainerProbeReport:
    """Listing + ACL + metadata probes against one blob container."""
    report = ContainerProbeReport(account=account, container=container)
    notes: list[str] = []
    # URL-encode the ``$`` in ``$web`` and friends.
    encoded = container.replace("$", "%24")
    base = f"https://{account}.blob.core.windows.net/{encoded}"

    try:
        list_resp = await client.get(
            f"{base}?restype=container&comp=list&maxresults=100"
        )
    except httpx.HTTPError as exc:
        notes.append(f"list: error: {exc.__class__.__name__}")
        list_resp = None

    if list_resp is not None:
        if list_resp.status_code == 200 and "<EnumerationResults" in (list_resp.text or ""):
            report.public_list = True
            report.blob_keys = _parse_blob_names(list_resp.text)
            notes.append(f"list: public ({len(report.blob_keys)} blobs shown)")
        elif list_resp.status_code in (403, 404, 409) and _is_azure_service(list_resp):
            report.public_list = False
            notes.append(f"list: denied (HTTP {list_resp.status_code})")
        else:
            notes.append(f"list: http_{list_resp.status_code}")

    try:
        acl_resp = await client.get(f"{base}?restype=container&comp=acl")
    except httpx.HTTPError as exc:
        notes.append(f"acl: error: {exc.__class__.__name__}")
    else:
        level = acl_resp.headers.get("x-ms-blob-public-access", "")
        if acl_resp.status_code == 200:
            report.public_access_level = level or "none"
            notes.append(f"acl: {level or 'none'}")
        else:
            notes.append(f"acl: http_{acl_resp.status_code}")

    try:
        meta_resp = await client.get(f"{base}?restype=container")
    except httpx.HTTPError as exc:
        notes.append(f"metadata: error: {exc.__class__.__name__}")
    else:
        if meta_resp.status_code == 200:
            report.metadata_200 = True
            notes.append("metadata: public")
        elif meta_resp.status_code == 404:
            report.metadata_200 = False
            notes.append("metadata: not_found")
        else:
            notes.append(f"metadata: http_{meta_resp.status_code}")

    report.summary = " · ".join(notes)
    return report


def _parse_blob_names(body: str) -> list[str]:
    if not body:
        return []
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return []
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}", 1)[0][1:]
    blobs_tag = f"{{{ns}}}Blobs" if ns else "Blobs"
    blob_tag = f"{{{ns}}}Blob" if ns else "Blob"
    name_tag = f"{{{ns}}}Name" if ns else "Name"
    blobs_node = root.find(blobs_tag)
    if blobs_node is None:
        return []
    names: list[str] = []
    for entry in blobs_node.findall(blob_tag):
        name_node = entry.find(name_tag)
        if name_node is not None and name_node.text:
            names.append(name_node.text)
    return names


async def scan_public_blobs(
    client: httpx.AsyncClient,
    account: str,
    container: str,
    keys: list[str],
    *,
    max_blobs: int,
    max_blob_size_kb: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Fetch text-like blobs from a public container and scan for secrets.

    Returns ``(sampled_metadata, secret_findings)`` — one row per blob
    actually fetched, and a flat list of regex hits stamped with the
    owning account/container for easy grouping.
    """
    sampled: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    if not keys:
        return sampled, findings
    encoded_container = container.replace("$", "%24")
    base = f"https://{account}.blob.core.windows.net/{encoded_container}"
    byte_cap = max_blob_size_kb * 1024
    headers = {"Range": f"bytes=0-{byte_cap - 1}"}
    picked = [k for k in keys if ext(k) in TEXT_EXTENSIONS][:max_blobs]

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
        hits = scan_text(f"azure://{account}/{container}/{key}", body)
        sampled.append(
            {
                "account": account,
                "container": container,
                "key": key,
                "size": len(resp.content),
                "bytes_scanned": len(raw),
                "secret_count": len(hits),
            }
        )
        for hit in hits:
            row = hit.as_dict()
            row["account"] = account
            row["container"] = container
            findings.append(row)
    return sampled, findings


# ---------------------------------------------------------------------------
# Bruteforce helpers
# ---------------------------------------------------------------------------


def bruteforce_accounts(
    prefixes: tuple[str, ...] | list[str],
    suffixes: list[str],
) -> list[str]:
    """Combine ``prefix`` + ``suffix`` into DNS-safe storage-account names.

    Azure storage accounts are **alnum-only**, no dashes / dots /
    underscores, so we can't reuse the S3 permutation set. We emit three
    shapes per pair: ``<p><s>``, ``<s><p>``, and ``<p><digit><s>`` with
    the digit sweeping 1..3 (a common prod/dev/qa convention).
    """
    if not prefixes or not suffixes:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for raw_prefix in prefixes:
        prefix = _strip_non_alnum(raw_prefix.lower())
        if not prefix:
            continue
        candidates: list[str] = [prefix]
        for raw_suffix in suffixes:
            suffix = _strip_non_alnum(raw_suffix.lower())
            if not suffix:
                continue
            candidates.extend(
                [
                    f"{prefix}{suffix}",
                    f"{suffix}{prefix}",
                    f"{prefix}1{suffix}",
                    f"{prefix}2{suffix}",
                    f"{prefix}3{suffix}",
                ]
            )
        for name in candidates:
            if name in seen:
                continue
            if not _VALID_ACCOUNT.match(name):
                continue
            seen.add(name)
            out.append(name)
    return out


def _strip_non_alnum(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value)


def load_default_suffix_wordlist() -> list[str]:
    """Bundled suffix list shipped under ``cloud_service_enum/data/``."""
    try:
        resource = files("cloud_service_enum.data").joinpath(
            "azure-storage-account-suffixes.txt"
        )
        text = resource.read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        return []
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
