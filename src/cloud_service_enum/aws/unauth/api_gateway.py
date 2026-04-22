"""API Gateway / Lambda Function URL extraction + unauth probes.

Pulls ``execute-api.amazonaws.com`` and ``lambda-url.on.aws`` references
out of crawled text bodies, classifies them (REST / HTTP / WebSocket /
Lambda URL) and probes each endpoint unauthenticated:

* ``GET /`` against the root / first stage to fingerprint existence and
  whether IAM auth is enforced.
* ``GET /openapi.json`` (+ common variants) to flag accidentally public
  OpenAPI specs — a goldmine for route discovery.
* A short list of obvious stage names (``prod``, ``dev``, …) for REST
  APIs only.
* ``OPTIONS /`` with a forged ``Origin`` header to detect wildcard /
  credentialed CORS misconfiguration.
* Lambda URLs: one ``GET /`` with an ``Origin`` header, classifying the
  response as ``AUTH_TYPE=NONE`` or ``AWS_IAM``.

Every HTTP call flows through the caller-supplied ``httpx.AsyncClient``
so the runner controls timeouts, concurrency, and retries.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx

from cloud_service_enum.aws.unauth.crawler import FetchedPage

REST_HTTP_RE = re.compile(
    r"\bhttps?://([a-z0-9]{10})\.execute-api\.([a-z0-9\-]+)\.amazonaws\.com(?:/([A-Za-z0-9_\-]+))?",
    re.IGNORECASE,
)
WEBSOCKET_RE = re.compile(
    r"\bwss?://([a-z0-9]{10})\.execute-api\.([a-z0-9\-]+)\.amazonaws\.com",
    re.IGNORECASE,
)
LAMBDA_URL_RE = re.compile(
    r"\bhttps?://([a-z0-9]+)\.lambda-url\.([a-z0-9\-]+)\.on\.aws",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ApiHit:
    """One API Gateway / Lambda URL reference surfaced during a crawl."""

    kind: str  # "rest" | "http" | "websocket" | "lambda_url"
    alias_or_id: str
    region: str
    stage: str
    url: str
    first_seen_url: str


@dataclass
class _RootProbeResult:
    status: str = "unknown"
    message: str = ""
    auth_required: str | None = None


@dataclass
class _CorsProbeResult:
    wildcard: bool | None = None
    credentials: bool | None = None
    summary: str = ""


@dataclass
class _StageProbeResult:
    detected: list[str] = field(default_factory=list)
    summary: str = ""


@dataclass
class _OpenApiProbeResult:
    exposed: bool = False
    exposed_at: str = ""
    title: str | None = None
    path_count: int = 0
    body_snippet: str | None = None


@dataclass
class _LambdaProbeResult:
    auth_type: str = "unknown"
    cors_wildcard: bool | None = None
    cors_credentials: bool | None = None
    root_status: str = "unknown"
    root_message: str = ""
    summary: str = ""


def extract_endpoints(pages: list[FetchedPage]) -> list[ApiHit]:
    """Return deduplicated API / Lambda URL references across every page body."""
    hits: dict[str, ApiHit] = {}

    for page in pages:
        body = page.body or ""
        if not body:
            continue
        for match in WEBSOCKET_RE.finditer(body):
            api_id = match.group(1).lower()
            region = match.group(2).lower()
            url = f"wss://{api_id}.execute-api.{region}.amazonaws.com"
            hits.setdefault(
                url,
                ApiHit(
                    kind="websocket",
                    alias_or_id=api_id,
                    region=region,
                    stage="",
                    url=url,
                    first_seen_url=page.url,
                ),
            )
        for match in REST_HTTP_RE.finditer(body):
            api_id = match.group(1).lower()
            region = match.group(2).lower()
            stage = (match.group(3) or "").strip("/") or ""
            base = f"https://{api_id}.execute-api.{region}.amazonaws.com"
            url = f"{base}/{stage}" if stage else base
            kind = _infer_rest_or_http(stage)
            hits.setdefault(
                url,
                ApiHit(
                    kind=kind,
                    alias_or_id=api_id,
                    region=region,
                    stage=stage,
                    url=url,
                    first_seen_url=page.url,
                ),
            )
        for match in LAMBDA_URL_RE.finditer(body):
            alias = match.group(1).lower()
            region = match.group(2).lower()
            url = f"https://{alias}.lambda-url.{region}.on.aws"
            hits.setdefault(
                url,
                ApiHit(
                    kind="lambda_url",
                    alias_or_id=alias,
                    region=region,
                    stage="",
                    url=url,
                    first_seen_url=page.url,
                ),
            )

    return list(hits.values())


def classify_direct_api_url(raw: str) -> ApiHit | None:
    """Classify an explicit ``--api-url`` input through the same regex set."""
    match = LAMBDA_URL_RE.match(raw)
    if match:
        alias, region = match.group(1).lower(), match.group(2).lower()
        url = f"https://{alias}.lambda-url.{region}.on.aws"
        return ApiHit(
            kind="lambda_url",
            alias_or_id=alias,
            region=region,
            stage="",
            url=url,
            first_seen_url="(--api-url)",
        )
    match = WEBSOCKET_RE.match(raw)
    if match:
        api_id, region = match.group(1).lower(), match.group(2).lower()
        url = f"wss://{api_id}.execute-api.{region}.amazonaws.com"
        return ApiHit(
            kind="websocket",
            alias_or_id=api_id,
            region=region,
            stage="",
            url=url,
            first_seen_url="(--api-url)",
        )
    match = REST_HTTP_RE.match(raw)
    if match:
        api_id = match.group(1).lower()
        region = match.group(2).lower()
        stage = (match.group(3) or "").strip("/") or ""
        base = f"https://{api_id}.execute-api.{region}.amazonaws.com"
        url = f"{base}/{stage}" if stage else base
        return ApiHit(
            kind=_infer_rest_or_http(stage),
            alias_or_id=api_id,
            region=region,
            stage=stage,
            url=url,
            first_seen_url="(--api-url)",
        )
    return None


def _infer_rest_or_http(stage: str) -> str:
    """REST APIs always publish under a stage path; HTTP APIs default to ``$default``.

    Without actively probing we can't be 100 % sure, but the presence of
    an explicit stage in the URL is a strong REST API indicator.
    """
    return "rest" if stage else "http"


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------


async def probe_api_root(
    client: httpx.AsyncClient, hit: ApiHit
) -> _RootProbeResult:
    """Classify the root / first stage of a REST or HTTP API."""
    url = hit.url.rstrip("/") + "/"
    try:
        resp = await client.get(url)
    except httpx.HTTPError as exc:
        return _RootProbeResult(status="error", message=f"{exc.__class__.__name__}: {exc}")

    body_snippet = (resp.text or "")[:200]
    message_field = _json_message(body_snippet)
    if resp.status_code == 403 and message_field == "Missing Authentication Token":
        return _RootProbeResult(
            status="exists",
            message="HTTP 403 Missing Authentication Token — IAM auth enforced",
            auth_required="yes",
        )
    if resp.status_code == 403 and message_field in ("Forbidden",):
        return _RootProbeResult(
            status="exists",
            message="HTTP 403 Forbidden — auth likely enforced",
            auth_required="yes",
        )
    if resp.status_code == 404 and message_field == "Not Found":
        return _RootProbeResult(
            status="exists",
            message="HTTP 404 — no matching route",
            auth_required="maybe",
        )
    if resp.status_code in (200, 301, 302):
        return _RootProbeResult(
            status="public",
            message=f"HTTP {resp.status_code} — root responds",
            auth_required="no",
        )
    return _RootProbeResult(
        status=f"http_{resp.status_code}",
        message=f"HTTP {resp.status_code}",
    )


async def probe_stages(
    client: httpx.AsyncClient, hit: ApiHit
) -> _StageProbeResult:
    """REST APIs only: peek at common stage names."""
    candidates = ("prod", "dev", "staging", "test", "v1", "v2", "api")
    if hit.kind != "rest":
        return _StageProbeResult(summary="skipped (non-rest)")
    base = f"https://{hit.alias_or_id}.execute-api.{hit.region}.amazonaws.com"
    detected: list[str] = []
    for stage in candidates:
        url = f"{base}/{stage}/"
        try:
            resp = await client.get(url)
        except httpx.HTTPError:
            continue
        if resp.status_code == 404:
            continue
        if resp.status_code in (200, 301, 302, 403):
            detected.append(stage)
    summary = ", ".join(detected) if detected else "none detected"
    return _StageProbeResult(detected=detected, summary=summary)


async def probe_openapi_leaks(
    client: httpx.AsyncClient, hit: ApiHit
) -> _OpenApiProbeResult:
    """Poke a handful of OpenAPI / Swagger paths for accidental exposure."""
    candidates = ("openapi.json", "swagger.json", "api-docs", "v1/openapi.json")
    roots: list[str] = [hit.url.rstrip("/")]
    if hit.kind == "http" and not hit.stage:
        roots.append(f"{hit.url.rstrip('/')}/default")

    for root in roots:
        for candidate in candidates:
            url = f"{root}/{candidate}"
            try:
                resp = await client.get(url)
            except httpx.HTTPError:
                continue
            if resp.status_code != 200:
                continue
            content_type = (resp.headers.get("content-type") or "").lower()
            if "json" not in content_type and not (resp.text or "").lstrip().startswith("{"):
                continue
            try:
                payload = resp.json()
            except (ValueError, json.JSONDecodeError):
                continue
            if not isinstance(payload, dict):
                continue
            paths = payload.get("paths") or {}
            title = (payload.get("info") or {}).get("title")
            body_snippet = json.dumps(payload, indent=2)[:4000]
            return _OpenApiProbeResult(
                exposed=True,
                exposed_at=url,
                title=str(title) if title else None,
                path_count=len(paths) if isinstance(paths, dict) else 0,
                body_snippet=body_snippet,
            )
    return _OpenApiProbeResult()


async def probe_cors(
    client: httpx.AsyncClient, url: str
) -> _CorsProbeResult:
    """``OPTIONS <url>`` with a forged ``Origin`` to detect overly-lax CORS."""
    headers = {
        "Origin": "https://example.invalid",
        "Access-Control-Request-Method": "GET",
    }
    target = url.rstrip("/") + "/"
    try:
        resp = await client.options(target, headers=headers)
    except httpx.HTTPError as exc:
        return _CorsProbeResult(summary=f"error: {exc.__class__.__name__}")
    allow_origin = (resp.headers.get("access-control-allow-origin") or "").strip()
    allow_creds = (resp.headers.get("access-control-allow-credentials") or "").strip().lower()
    wildcard = allow_origin == "*"
    echoed = allow_origin == "https://example.invalid"
    credentials = allow_creds == "true"
    notes: list[str] = []
    if wildcard:
        notes.append("ACAO: *")
    if echoed:
        notes.append("ACAO echoes arbitrary origin")
    if credentials:
        notes.append("ACAC: true")
    if not allow_origin:
        notes.append("no ACAO header")
    summary = " · ".join(notes) if notes else "no CORS findings"
    return _CorsProbeResult(
        wildcard=wildcard or (echoed and credentials) or None,
        credentials=credentials,
        summary=summary,
    )


async def probe_lambda_url(
    client: httpx.AsyncClient, url: str
) -> _LambdaProbeResult:
    """Single ``GET /`` against a Lambda URL to fingerprint AUTH_TYPE."""
    headers = {"Origin": "https://example.invalid"}
    target = url.rstrip("/") + "/"
    try:
        resp = await client.get(target, headers=headers)
    except httpx.HTTPError as exc:
        return _LambdaProbeResult(
            root_status="error",
            root_message=f"{exc.__class__.__name__}: {exc}",
            summary=f"error: {exc.__class__.__name__}",
        )
    snippet = (resp.text or "")[:200]
    message = _json_message(snippet)
    auth_type = "unknown"
    root_status = f"http_{resp.status_code}"
    if resp.status_code in (200, 301, 302):
        auth_type = "NONE"
        root_status = "public"
    elif resp.status_code == 403 and message in ("Forbidden", "Missing Authentication Token"):
        auth_type = "AWS_IAM"
        root_status = "auth_required"
    elif resp.status_code == 404:
        auth_type = "NONE (no route at /)"
        root_status = "exists"

    allow_origin = (resp.headers.get("access-control-allow-origin") or "").strip()
    allow_creds = (resp.headers.get("access-control-allow-credentials") or "").strip().lower()
    cors_wildcard = allow_origin == "*"
    cors_echo = allow_origin == "https://example.invalid"
    cors_credentials = allow_creds == "true"

    parts = [f"HTTP {resp.status_code}", f"AUTH_TYPE={auth_type}"]
    if cors_wildcard:
        parts.append("ACAO: *")
    elif cors_echo and cors_credentials:
        parts.append("ACAO echoes origin + ACAC: true")
    return _LambdaProbeResult(
        auth_type=auth_type,
        cors_wildcard=cors_wildcard or (cors_echo and cors_credentials) or None,
        cors_credentials=cors_credentials,
        root_status=root_status,
        root_message=f"HTTP {resp.status_code}: {message or snippet[:120]}",
        summary=" · ".join(parts),
    )


def _json_message(snippet: str) -> str:
    """Best-effort extraction of ``message`` / ``Message`` from a JSON body."""
    if not snippet or not snippet.lstrip().startswith("{"):
        return ""
    try:
        payload = json.loads(snippet)
    except (ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(payload, dict):
        return ""
    return str(payload.get("message") or payload.get("Message") or "")


def host_of(url: str) -> str:
    return urlparse(url).netloc.lower()
