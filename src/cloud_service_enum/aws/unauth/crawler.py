"""Async same-origin crawler for unauthenticated web-app recon.

Performs a recursive BFS starting from one entry URL. The crawler
follows references to text-like resources (HTML, JS, JSON, source-map,
plain text) only — binary assets such as images, fonts, video, or
fetches that exceed :data:`MAX_BODY_BYTES` are recorded as visited but
their bodies are dropped.

References are extracted with deliberately lenient regexes so that
webpack/Vite/Next.js bundles, dynamic ``import()`` calls, manifest JSON
files, and inline ``<script>`` tags all surface their child URLs without
needing a real DOM or JS parser. Callers regex over the returned bodies
themselves to look for whatever they care about (Cognito IDs, API
Gateway hosts, …).
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from urllib.parse import urldefrag, urljoin, urlparse

import httpx

MAX_BODY_BYTES = 5 * 1024 * 1024  # 5 MB
DEFAULT_USER_AGENT = "cloud-service-enum/2.0 (+unauth)"
TEXTUAL_CONTENT_TYPES: tuple[str, ...] = (
    "text/",
    "application/json",
    "application/javascript",
    "application/ecmascript",
    "application/xml",
    "application/xhtml",
    "application/manifest",
    "application/ld+json",
    "image/svg",  # SVGs sometimes embed <script>
)
SKIP_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".tif", ".tiff",
        ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".mp4", ".webm", ".mov", ".avi", ".mp3", ".wav", ".ogg", ".flac",
        ".pdf", ".zip", ".gz", ".tar", ".7z", ".rar",
    }
)

_SCRIPT_SRC = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.IGNORECASE)
_LINK_HREF = re.compile(r"""<link[^>]+href=["']([^"']+)["']""", re.IGNORECASE)
_ANCHOR_HREF = re.compile(r"""<a[^>]+href=["']([^"']+)["']""", re.IGNORECASE)
_INLINE_SCRIPT = re.compile(
    r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL
)
_HTTP_URL = re.compile(r"""["'`](https?://[^"'`\s<>]+)["'`]""")
_RELATIVE_ASSET = re.compile(
    r"""["'`]((?:\.{0,2}/)?[A-Za-z0-9_\-./]+\.(?:js|mjs|cjs|json|map))["'`]"""
)
# Webpack chunk maps: {1234:"abcd1234"} or "1234":"abcd1234"
_WEBPACK_CHUNK = re.compile(
    r"""["']?([0-9A-Za-z_-]+)["']?\s*:\s*["']([0-9a-f]{6,})["']"""
)


@dataclass(frozen=True)
class CrawlScope:
    """Inputs that bound a single crawl."""

    start_url: str
    max_pages: int = 250
    max_concurrency: int = 10
    timeout_s: float = 15.0
    user_agent: str = DEFAULT_USER_AGENT
    extra_hosts: tuple[str, ...] = ()


@dataclass
class FetchedPage:
    """Result of one HTTP fetch during the crawl."""

    url: str
    status: int = 0
    content_type: str = ""
    body: str | None = None
    error: str | None = None
    bytes_read: int = 0


@dataclass
class CrawlStats:
    """Aggregate counters returned alongside the page list."""

    pages_fetched: int = 0
    js_files: int = 0
    bytes_downloaded: int = 0
    same_origin_hosts: set[str] = field(default_factory=set)


async def crawl(scope: CrawlScope) -> tuple[list[FetchedPage], CrawlStats]:
    """Crawl ``scope.start_url`` recursively, returning every fetched page.

    BFS by waves: every URL discovered in wave ``N`` is fetched together
    in wave ``N+1``, bounded by ``max_concurrency``. The wave model keeps
    termination obvious (no in-flight counter races) and wave size is
    naturally throttled by the semaphore.
    """
    start = _normalise(scope.start_url)
    if not start:
        return [], CrawlStats()
    in_scope_hosts = _build_scope_hosts(start, scope.extra_hosts)

    visited: set[str] = {start}
    pages: list[FetchedPage] = []
    stats = CrawlStats(same_origin_hosts=set(in_scope_hosts))
    sem = asyncio.Semaphore(scope.max_concurrency)
    frontier: list[str] = [start]

    async with httpx.AsyncClient(
        timeout=scope.timeout_s,
        headers={"User-Agent": scope.user_agent},
        follow_redirects=True,
        max_redirects=5,
    ) as client:
        while frontier and len(visited) <= scope.max_pages:
            results = await asyncio.gather(
                *[_fetch(client, sem, url) for url in frontier]
            )
            next_frontier: list[str] = []
            for page in results:
                pages.append(page)
                stats.pages_fetched += 1
                stats.bytes_downloaded += page.bytes_read
                if page.body and _looks_like_js(page):
                    stats.js_files += 1
                if not page.body:
                    continue
                for child in _extract_urls(page):
                    if len(visited) >= scope.max_pages:
                        break
                    normalised = _normalise(child)
                    if not normalised or normalised in visited:
                        continue
                    host = urlparse(normalised).netloc.lower()
                    if host not in in_scope_hosts:
                        continue
                    visited.add(normalised)
                    next_frontier.append(normalised)
            frontier = next_frontier

    return pages, stats


async def _fetch(
    client: httpx.AsyncClient, sem: asyncio.Semaphore, url: str
) -> FetchedPage:
    async with sem:
        try:
            resp = await client.get(url)
        except httpx.HTTPError as exc:
            return FetchedPage(url=url, error=f"{exc.__class__.__name__}: {exc}")
        except Exception as exc:  # noqa: BLE001
            return FetchedPage(url=url, error=f"{exc.__class__.__name__}: {exc}")

    content_type = (resp.headers.get("content-type") or "").split(";")[0].strip().lower()
    page = FetchedPage(url=str(resp.url), status=resp.status_code, content_type=content_type)

    if resp.status_code >= 400:
        page.error = f"HTTP {resp.status_code}"
    if not _is_textual(content_type, str(resp.url)):
        return page

    raw = resp.content
    page.bytes_read = len(raw)
    if len(raw) > MAX_BODY_BYTES:
        page.error = f"body exceeded {MAX_BODY_BYTES} bytes ({len(raw)})"
        return page
    try:
        page.body = raw.decode(resp.encoding or "utf-8", errors="replace")
    except (LookupError, ValueError):
        page.body = raw.decode("utf-8", errors="replace")
    return page


def _build_scope_hosts(start_url: str, extra: tuple[str, ...]) -> set[str]:
    hosts = {urlparse(start_url).netloc.lower()}
    for host in extra:
        cleaned = host.strip().lower()
        if cleaned:
            hosts.add(cleaned)
    return hosts


def _normalise(url: str) -> str:
    """Return a canonical form for ``url`` (drop fragment, force scheme)."""
    if not url:
        return ""
    cleaned = url.strip()
    if cleaned.startswith("//"):
        cleaned = "https:" + cleaned
    if not cleaned.lower().startswith(("http://", "https://")):
        return ""
    no_frag, _ = urldefrag(cleaned)
    return no_frag


def _is_textual(content_type: str, url: str) -> bool:
    if content_type.startswith(TEXTUAL_CONTENT_TYPES):
        return True
    if not content_type:
        path = urlparse(url).path.lower()
        for skip in SKIP_EXTENSIONS:
            if path.endswith(skip):
                return False
        return True
    return False


def _looks_like_js(page: FetchedPage) -> bool:
    if "javascript" in page.content_type or "ecmascript" in page.content_type:
        return True
    return urlparse(page.url).path.lower().endswith((".js", ".mjs", ".cjs"))


def _extract_urls(page: FetchedPage) -> list[str]:
    """Pull every plausible same-origin URL from ``page.body``."""
    body = page.body or ""
    base = page.url
    out: list[str] = []
    seen: set[str] = set()

    def _push(candidate: str) -> None:
        resolved = _resolve(base, candidate)
        if resolved and resolved not in seen:
            seen.add(resolved)
            out.append(resolved)

    is_html = "html" in page.content_type or body.lstrip().lower().startswith("<")
    if is_html:
        for match in _SCRIPT_SRC.finditer(body):
            _push(match.group(1))
        for match in _LINK_HREF.finditer(body):
            _push(match.group(1))
        for match in _ANCHOR_HREF.finditer(body):
            _push(match.group(1))
        for match in _INLINE_SCRIPT.finditer(body):
            _harvest_strings(match.group(1), base, _push)
    else:
        _harvest_strings(body, base, _push)

    return out


def _harvest_strings(text: str, base: str, push) -> None:
    for match in _HTTP_URL.finditer(text):
        push(match.group(1))
    for match in _RELATIVE_ASSET.finditer(text):
        push(match.group(1))
    # Webpack chunk manifests: turn entries into ``./<chunk>.<hash>.js``.
    base_dir = base.rsplit("/", 1)[0] + "/"
    for match in _WEBPACK_CHUNK.finditer(text):
        chunk_id, content_hash = match.group(1), match.group(2)
        # Heuristic: most webpack manifests load chunks as `<id>.<hash>.js`.
        push(f"{base_dir}{chunk_id}.{content_hash}.js")


def _resolve(base: str, candidate: str) -> str:
    if not candidate or candidate.startswith(("data:", "javascript:", "mailto:", "tel:")):
        return ""
    try:
        joined = urljoin(base, candidate)
    except ValueError:
        return ""
    return _normalise(joined)
