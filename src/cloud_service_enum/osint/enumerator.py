"""Async OSINT entry point.

Discovers subdomains from a wordlist plus Certificate Transparency logs,
resolves them, attributes the resolved IPs to cloud providers via RDAP
ownership lookups, and probes for an Azure tenant id. Everything is
returned as a single :class:`EnumerationRun` whose ``domains`` service
holds rows of three kinds: ``domain``, ``cloud_provider``, ``tenant``.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx

try:
    import dns.asyncresolver
    import dns.resolver
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

CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"
CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
AZURE_TENANT_URL = "https://login.microsoftonline.com/{domain}/.well-known/openid-configuration"
RDAP_URL = "https://rdap.arin.net/registry/ip/{ip}"
USER_AGENT = "cloud-service-enum/2.0 (+osint)"

# Substrings that map a RDAP "organisation" name onto a friendly
# cloud-provider label. Order matters only for ties; first match wins.
_ORG_TO_PROVIDER: tuple[tuple[str, str], ...] = (
    ("amazon", "AWS"),
    ("a100 row", "AWS"),
    ("microsoft", "Azure"),
    ("google", "GCP"),
    ("cloudflare", "Cloudflare"),
    ("fastly", "Fastly"),
    ("akamai", "Akamai"),
    ("digitalocean", "DigitalOcean"),
    ("oracle", "Oracle Cloud"),
    ("alibaba", "Alibaba Cloud"),
    ("ovh", "OVH"),
    ("hetzner", "Hetzner"),
    ("linode", "Linode"),
    ("vultr", "Vultr"),
    ("github", "GitHub"),
    ("netlify", "Netlify"),
    ("vercel", "Vercel"),
)

# CNAME / A-record string patterns used as a fallback when RDAP is
# unavailable or returns nothing useful. Lowercase substring matches.
_CNAME_PROVIDER_HINTS: dict[str, tuple[str, ...]] = {
    "AWS": ("amazonaws.com", "cloudfront.net", "elb.amazonaws", "execute-api"),
    "Azure": (
        "azurewebsites.net",
        "azureedge.net",
        "blob.core.windows.net",
        "cloudapp.net",
        "trafficmanager.net",
    ),
    "GCP": ("googleusercontent.com", "appspot.com", "cloudfunctions.net", "run.app"),
    "Cloudflare": ("cloudflare",),
    "Fastly": ("fastly",),
}


@dataclass
class OsintScope:
    """Input configuration for a single OSINT run."""

    domain: str
    wordlist: list[str] = field(default_factory=list)
    max_concurrency: int = 40
    http_timeout_s: float = 15.0
    brute_force: bool = True
    ct_logs: bool = True
    rdap: bool = True
    azure_tenant: bool = True
    whois: bool = False
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
        iam_policy_bodies=False,
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
            "Brute force": "yes" if scope.brute_force else "no",
            "Wordlist size": len(wordlist) if scope.brute_force else 0,
            "Certificate transparency": "yes" if scope.ct_logs else "no",
            "RDAP IP lookup": "yes" if scope.rdap else "no",
            "Azure tenant probe": "yes" if scope.azure_tenant else "no",
            "WHOIS (domain)": "yes" if scope.whois else "no",
            "Extra hostnames": len(scope.extra_hostnames),
        },
    )

    svc_started = datetime.now(timezone.utc)
    async with httpx.AsyncClient(
        timeout=scope.http_timeout_s,
        headers={"User-Agent": USER_AGENT},
        follow_redirects=True,
    ) as http:
        brute_hits = (
            await _brute_force(scope.domain, wordlist, scope) if scope.brute_force else []
        )
        ct_records = await _ct_logs(scope, http) if scope.ct_logs else {}

        sources: dict[str, str] = {}
        issued: dict[str, str] = {}
        for host in brute_hits:
            sources.setdefault(host, "brute")
        for host, meta in ct_records.items():
            sources.setdefault(host, meta["source"])
            if meta.get("issued"):
                issued.setdefault(host, meta["issued"])
        for host in scope.extra_hostnames:
            sources.setdefault(host.lower(), "extra")

        candidates = sorted(sources)
        resolved = await _resolve_all(candidates, scope)

        ips = sorted({ip for rec in resolved.values() for ip in rec.get("A", [])})
        ip_orgs = await _rdap_lookup(ips, http, scope) if scope.rdap and ips else {}
        tenant = (
            await _azure_tenant(scope, http) if scope.azure_tenant else None
        )
        whois_record = await _whois(scope) if scope.whois else {}

    domain_rows = _build_domain_rows(resolved, sources, issued, ip_orgs)
    provider_rows = _build_provider_rows(domain_rows)
    tenant_rows = _build_tenant_rows(scope.domain, tenant)

    domain_service = ServiceResult(
        provider=Provider.OSINT,
        service="domains",
        started_at=svc_started,
        resources=[*domain_rows, *provider_rows, *tenant_rows],
        cis_fields={
            "subdomain_count": len(domain_rows),
            "brute_force_hits": len(brute_hits),
            "ct_hits": len(ct_records),
            "rdap_lookups": len(ip_orgs),
            "azure_tenant_id": tenant,
            "providers": sorted(
                {r["provider"] for r in domain_rows if r.get("provider") and r["provider"] != "-"}
            ),
            "whois": whois_record,
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


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


async def _brute_force(domain: str, wordlist: list[str], scope: OsintScope) -> list[str]:
    if dns is None:
        return []
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = scope.http_timeout_s
    resolver.lifetime = scope.http_timeout_s

    async def _probe(sub: str) -> str | None:
        host = f"{sub}.{domain}".lower()
        try:
            await resolver.resolve(host, "A")
        except Exception:  # noqa: BLE001
            return None
        return host

    results = await bounded_gather(
        [_probe(s) for s in wordlist], max_concurrency=scope.max_concurrency
    )
    return sorted({r for r in results if isinstance(r, str)})


async def _ct_logs(
    scope: OsintScope, http: httpx.AsyncClient
) -> dict[str, dict[str, str]]:
    """Pull subdomains from Certificate Transparency logs.

    Tries certspotter first (clean JSON, fast, generous quota), then
    falls back to crt.sh on failure / empty result.
    """
    out = await _ct_certspotter(scope, http)
    if out:
        return out
    return await _ct_crtsh(scope, http)


async def _ct_certspotter(
    scope: OsintScope, http: httpx.AsyncClient
) -> dict[str, dict[str, str]]:
    params = {
        "domain": scope.domain,
        "include_subdomains": "true",
        "expand": "dns_names",
    }
    try:
        resp = await http.get(CERTSPOTTER_URL, params=params)
        if resp.status_code != 200:
            return {}
        data = resp.json()
    except Exception:  # noqa: BLE001
        return {}
    out: dict[str, dict[str, str]] = {}
    for entry in data or []:
        issued = str(entry.get("not_before") or "")[:10]
        for raw in entry.get("dns_names") or []:
            host = str(raw).strip().lower().lstrip("*.")
            if not host or "*" in host:
                continue
            if scope.domain not in host:
                continue
            out.setdefault(host, {"source": "ct:certspotter", "issued": issued})
    return out


async def _ct_crtsh(
    scope: OsintScope, http: httpx.AsyncClient
) -> dict[str, dict[str, str]]:
    try:
        resp = await http.get(CRTSH_URL.format(domain=scope.domain))
        if resp.status_code != 200:
            return {}
        data = resp.json()
    except Exception:  # noqa: BLE001
        return {}
    out: dict[str, dict[str, str]] = {}
    for entry in data or []:
        issued = str(entry.get("not_before") or "")[:10]
        for raw in (entry.get("name_value") or "").splitlines():
            host = raw.strip().lower().lstrip("*.")
            if not host or "*" in host or scope.domain not in host:
                continue
            out.setdefault(host, {"source": "ct:crt.sh", "issued": issued})
    return out


async def _resolve_all(
    hosts: list[str], scope: OsintScope
) -> dict[str, dict[str, list[str]]]:
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

    results = await bounded_gather(
        [_one(h) for h in hosts], max_concurrency=scope.max_concurrency
    )
    return {h: rec for item in results if isinstance(item, tuple) for h, rec in [item]}


# ---------------------------------------------------------------------------
# Enrichment
# ---------------------------------------------------------------------------


async def _rdap_lookup(
    ips: list[str], http: httpx.AsyncClient, scope: OsintScope
) -> dict[str, str]:
    """Look up the registered organisation for each IP via RDAP.

    ARIN's RDAP gateway transparently redirects to the right RIR (RIPE,
    APNIC, …) so a single endpoint covers the global address space.
    """
    sem = asyncio.Semaphore(min(scope.max_concurrency, 16))

    async def _one(ip: str) -> tuple[str, str] | None:
        async with sem:
            try:
                resp = await http.get(RDAP_URL.format(ip=ip))
                if resp.status_code != 200:
                    return None
                data = resp.json()
            except Exception:  # noqa: BLE001
                return None
        org = _extract_rdap_org(data)
        return (ip, org) if org else None

    results = await asyncio.gather(*[_one(ip) for ip in ips])
    return {ip: org for item in results if item for ip, org in [item]}


def _extract_rdap_org(data: dict[str, Any]) -> str | None:
    """Pluck the most useful organisation name out of an RDAP response.

    Prefers the human-readable ``fn`` / ``org`` field on a registrant
    entity's vcard (e.g. "Amazon Technologies Inc.", "Microsoft
    Corporation") over the short opaque handle ARIN puts on the
    top-level ``name`` (e.g. "AT-88-Z", "MSFT").
    """
    vcard_names: list[str] = []
    fallbacks: list[str] = []

    for entity in data.get("entities") or []:
        roles = entity.get("roles") or []
        if not any(r in roles for r in ("registrant", "administrative", "technical")):
            continue
        vcard = entity.get("vcardArray") or []
        if len(vcard) >= 2 and isinstance(vcard[1], list):
            for item in vcard[1]:
                if (
                    isinstance(item, list)
                    and len(item) >= 4
                    and item[0] in ("fn", "org")
                ):
                    text = _vcard_text(item[3])
                    if text:
                        vcard_names.append(text)
        if entity.get("handle"):
            fallbacks.append(str(entity["handle"]))

    if data.get("name"):
        fallbacks.append(str(data["name"]))

    for candidate in (*vcard_names, *fallbacks):
        cleaned = candidate.strip()
        if cleaned and not cleaned.upper().startswith("AS"):
            return cleaned
    return None


def _vcard_text(value: Any) -> str:
    """Flatten a vcard value (string or list of strings) to a single string."""
    if isinstance(value, list):
        return " ".join(str(v) for v in value if v).strip()
    return str(value or "").strip()


async def _azure_tenant(scope: OsintScope, http: httpx.AsyncClient) -> str | None:
    try:
        resp = await http.get(AZURE_TENANT_URL.format(domain=scope.domain))
        if resp.status_code != 200:
            return None
        data = resp.json()
    except Exception:  # noqa: BLE001
        return None
    issuer = data.get("issuer", "")
    match = re.search(r"/([0-9a-f-]{36})/", issuer)
    return match.group(1) if match else None


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


# ---------------------------------------------------------------------------
# Row assembly
# ---------------------------------------------------------------------------


def _build_domain_rows(
    resolved: dict[str, dict[str, list[str]]],
    sources: dict[str, str],
    issued: dict[str, str],
    ip_orgs: dict[str, str],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for host, records in sorted(resolved.items()):
        ips = records.get("A", [])
        orgs = sorted({ip_orgs[ip] for ip in ips if ip in ip_orgs})
        provider = _attribute_provider(orgs, records)
        rows.append(
            {
                "kind": "domain",
                "id": host,
                "name": host,
                "ip_addresses": ", ".join(ips) if ips else None,
                "provider": provider or "-",
                "organization": ", ".join(orgs) if orgs else "-",
                "source": sources.get(host, "resolved"),
                "issued": issued.get(host) or None,
                "records": records,
            }
        )
    # Hosts that were discovered but didn't resolve still get a row so
    # the user can see the source attribution.
    for host in sorted(set(sources) - set(resolved)):
        rows.append(
            {
                "kind": "domain",
                "id": host,
                "name": host,
                "ip_addresses": None,
                "provider": "-",
                "organization": "-",
                "source": sources[host],
                "issued": issued.get(host) or None,
            }
        )
    return rows


def _build_provider_rows(domain_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for row in domain_rows:
        provider = row.get("provider")
        if not provider or provider == "-":
            continue
        ips = (row.get("ip_addresses") or "").split(", ") if row.get("ip_addresses") else []
        bucket = grouped.setdefault(
            provider,
            {
                "kind": "cloud_provider",
                "id": provider,
                "name": provider,
                "ip_addresses": set(),
                "domain_count": 0,
            },
        )
        bucket["ip_addresses"].update(ip for ip in ips if ip)
        bucket["domain_count"] += 1
    rows: list[dict[str, Any]] = []
    for provider in sorted(grouped):
        bucket = grouped[provider]
        bucket["ip_addresses"] = ", ".join(sorted(bucket["ip_addresses"])) or "-"
        rows.append(bucket)
    return rows


def _build_tenant_rows(domain: str, tenant: str | None) -> list[dict[str, Any]]:
    if not tenant:
        return []
    return [
        {
            "kind": "tenant",
            "id": tenant,
            "name": domain,
            "tenant_id": tenant,
            "source": "Azure OIDC discovery",
        }
    ]


def _attribute_provider(orgs: list[str], records: dict[str, list[str]]) -> str | None:
    """Map RDAP organisation names (or DNS records) onto a provider label."""
    for org in orgs:
        lowered = org.lower()
        for needle, label in _ORG_TO_PROVIDER:
            if needle in lowered:
                return label
    text = " ".join(val for vals in records.values() for val in vals).lower()
    for label, patterns in _CNAME_PROVIDER_HINTS.items():
        if any(p in text for p in patterns):
            return label
    return None
