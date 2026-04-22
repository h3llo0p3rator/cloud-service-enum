"""Async OSINT entry point.

The OSINT module is structurally distinct from cloud enumerators — it
has no credentials and returns a synthetic :class:`ServiceResult` with
kind ``domain`` for each subdomain it discovers, plus aggregate summary
fields (WHOIS, cloud-provider attribution, Azure tenant).
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx

try:
    import dns.resolver
    import dns.asyncresolver
except ImportError:  # pragma: no cover - optional
    dns = None  # type: ignore[assignment]

from cloud_service_enum.core.concurrency import bounded_gather
from cloud_service_enum.core.display import (
    render_config,
    render_identity,
    render_service,
    render_summary,
)
from cloud_service_enum.core.models import EnumerationRun, Provider, Scope, ServiceResult
from cloud_service_enum.core.output import get_console
from cloud_service_enum.data import load_lines

CT_URL = "https://crt.sh/?q=%25.{domain}&output=json"
AZURE_TENANT_URL = "https://login.microsoftonline.com/{domain}/.well-known/openid-configuration"


@dataclass
class OsintScope:
    """Input configuration for a single OSINT run."""

    domain: str
    wordlist: list[str] = field(default_factory=list)
    max_concurrency: int = 40
    http_timeout_s: float = 10.0
    ct_logs: bool = True
    whois: bool = True
    ssl_inspect: bool = False
    extra_hostnames: list[str] = field(default_factory=list)


async def run_osint(scope: OsintScope) -> EnumerationRun:
    """Run subdomain discovery and enrichment for ``scope.domain``."""
    console = get_console()
    started = datetime.now(timezone.utc)
    wordlist = scope.wordlist or load_lines("subdomains.txt")

    cse_scope = Scope(
        provider=Provider.OSINT,
        services=["domains"],
        max_concurrency=scope.max_concurrency,
        timeout_s=scope.http_timeout_s,
    )
    identity = {
        "provider": Provider.OSINT.value,
        "principal": scope.domain,
        "auth_method": "none",
    }
    render_identity(console, identity)
    render_config(
        console,
        Provider.OSINT,
        cse_scope,
        extras={
            "Wordlist size": len(wordlist),
            "CT logs": "yes" if scope.ct_logs else "no",
            "WHOIS": "yes" if scope.whois else "no",
            "Extra hostnames": len(scope.extra_hostnames),
        },
    )

    svc_started = datetime.now(timezone.utc)
    brute = await _brute_force(scope.domain, wordlist, scope)
    ct = await _ct_logs(scope) if scope.ct_logs else []
    candidates = sorted({*brute, *ct, *scope.extra_hostnames})
    resolved = await _resolve_all(candidates, scope)

    whois_record = await _whois(scope) if scope.whois else {}
    tenant = await _azure_tenant(scope)

    domain_service = ServiceResult(
        provider=Provider.OSINT,
        service="domains",
        started_at=svc_started,
        resources=[
            {
                "kind": "domain",
                "id": host,
                "name": host,
                "providers": ", ".join(_cloud_hints(records)) or None,
                "records": records,
            }
            for host, records in resolved.items()
        ],
        cis_fields={
            "subdomain_count": len(resolved),
            "whois": whois_record,
            "azure_tenant_id": tenant,
            "brute_force_hits": len(brute),
            "ct_hits": len(ct),
        },
    )
    finished = datetime.now(timezone.utc)
    domain_service.finished_at = finished
    domain_service.duration_s = round((finished - svc_started).total_seconds(), 3)

    run = EnumerationRun(
        provider=Provider.OSINT,
        scope=cse_scope,
        identity=identity,
        services=[domain_service],
        started_at=started,
        finished_at=finished,
        duration_s=round((finished - started).total_seconds(), 3),
    )
    render_service(console, domain_service)
    render_summary(console, run)
    return run


async def _brute_force(domain: str, wordlist: list[str], scope: OsintScope) -> list[str]:
    if dns is None:
        return []
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = scope.http_timeout_s
    resolver.lifetime = scope.http_timeout_s

    async def _probe(sub: str) -> str | None:
        host = f"{sub}.{domain}"
        try:
            await resolver.resolve(host, "A")
        except Exception:  # noqa: BLE001
            return None
        return host

    results = await bounded_gather(
        [_probe(s) for s in wordlist], max_concurrency=scope.max_concurrency
    )
    return [r for r in results if isinstance(r, str)]


async def _ct_logs(scope: OsintScope) -> list[str]:
    url = CT_URL.format(domain=scope.domain)
    try:
        async with httpx.AsyncClient(timeout=scope.http_timeout_s) as client:
            resp = await client.get(url, headers={"User-Agent": "cloud-service-enum/2.0"})
            resp.raise_for_status()
            data = resp.json()
    except Exception:  # noqa: BLE001
        return []
    names: set[str] = set()
    for entry in data or []:
        for n in (entry.get("name_value") or "").splitlines():
            n = n.strip().lower()
            if n and scope.domain in n and "*" not in n:
                names.add(n)
    return sorted(names)


async def _resolve_all(hosts: list[str], scope: OsintScope) -> dict[str, dict[str, list[str]]]:
    if dns is None or not hosts:
        return {}
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = scope.http_timeout_s
    resolver.lifetime = scope.http_timeout_s

    async def _one(host: str) -> tuple[str, dict[str, list[str]]] | None:
        record: dict[str, list[str]] = {}
        for rtype in ("A", "AAAA", "CNAME", "MX", "TXT"):
            try:
                answers = await resolver.resolve(host, rtype)
                record[rtype] = [str(r).strip('"') for r in answers]
            except Exception:  # noqa: BLE001
                continue
        if not record:
            return None
        return host, record

    results = await bounded_gather([_one(h) for h in hosts], max_concurrency=scope.max_concurrency)
    return {h: rec for item in results if isinstance(item, tuple) for h, rec in [item]}


def _cloud_hints(records: dict[str, list[str]]) -> list[str]:
    """Infer cloud provider from CNAME/A targets."""
    hits: set[str] = set()
    texts = [val for vals in records.values() for val in vals]
    joined = " ".join(texts).lower()
    for provider, patterns in _PROVIDER_HINTS.items():
        if any(re.search(p, joined) for p in patterns):
            hits.add(provider)
    return sorted(hits)


_PROVIDER_HINTS = {
    "aws": [r"amazonaws\.com", r"cloudfront\.net", r"elb\.amazonaws", r"s3[-.]", r"execute-api"],
    "azure": [r"azurewebsites\.net", r"azureedge\.net", r"blob\.core\.windows\.net", r"cloudapp\.net"],
    "gcp": [r"googleusercontent\.com", r"appspot\.com", r"cloudfunctions\.net", r"run\.app"],
    "cloudflare": [r"cloudflare"],
    "fastly": [r"fastly"],
}


async def _whois(scope: OsintScope) -> dict[str, Any]:
    try:
        import whois  # type: ignore[import-not-found]
    except ImportError:
        return {}
    try:
        record = await asyncio.to_thread(whois.whois, scope.domain)
    except Exception:  # noqa: BLE001
        return {}
    return {k: str(v) for k, v in dict(record).items() if v}


async def _azure_tenant(scope: OsintScope) -> str | None:
    url = AZURE_TENANT_URL.format(domain=scope.domain)
    try:
        async with httpx.AsyncClient(timeout=scope.http_timeout_s) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return None
            data = resp.json()
    except Exception:  # noqa: BLE001
        return None
    issuer = data.get("issuer", "")
    match = re.search(r"/([0-9a-f-]{36})/", issuer)
    return match.group(1) if match else None
