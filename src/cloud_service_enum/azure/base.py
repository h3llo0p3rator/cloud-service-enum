"""Shared base class for every Azure service enumerator.

Azure SDKs are per-subscription; this base fans out over
``scope.subscription_ids`` and calls :meth:`collect` once per
subscription with the already-constructed management client.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from azure.core.exceptions import HttpResponseError

from cloud_service_enum.azure.auth import AzureAuthenticator
from cloud_service_enum.core.auth import CloudAuthenticator
from cloud_service_enum.core.concurrency import bounded_gather
from cloud_service_enum.core.errors import EnumerationError
from cloud_service_enum.core.models import Provider, Scope, ServiceResult


def _format_http_error(exc: HttpResponseError) -> str:
    """Trim the noisy duplicate ``Code:/Message:`` suffix from ARM errors.

    ``HttpResponseError.message`` typically contains the full human message
    followed by ``\\nCode: X\\nMessage: <same text>`` repeated. We only want
    the first block plus the HTTP status code.
    """
    raw = exc.message or str(exc)
    head = raw.split("\nCode:", 1)[0].strip()
    status = getattr(exc, "status_code", None) or getattr(exc.response, "status_code", None)
    return f"{status} {head}" if status else head


def _looks_like_graph_error(exc: Exception) -> bool:
    """Heuristic: is this an msgraph/Kiota ``APIError`` / ``ODataError``?"""
    name = type(exc).__name__
    return name in {"APIError", "ODataError"} or hasattr(exc, "error")


def _format_graph_error(exc: Exception) -> str:
    """Render a msgraph/Kiota ``APIError`` / ``ODataError`` as one terse line.

    The msgraph SDK stringifies exceptions with a full Python repr that
    dumps 20+ lines of ``MainError(...)``, ``InnerError(...)`` etc.
    Attackers/admins only care about the HTTP code and the human message,
    so we dig those out directly and fall back to ``type: message``.
    """
    err = getattr(exc, "error", None)
    code = getattr(exc, "response_status_code", None) or getattr(exc, "status_code", None)
    message = getattr(err, "message", None) or getattr(err, "code", None)
    label = getattr(err, "code", None)
    if message:
        bits = [f"{code}" if code else None, label, message]
        return " ".join(b for b in bits if b)
    return f"{type(exc).__name__}: {exc}".splitlines()[0][:200]


class AzureService(ABC):
    """Base class shared by every Azure service enumerator.

    Subclasses either implement :meth:`collect_subscription` (if they
    run per-subscription) or override :meth:`collect_tenant` (for
    tenant-scoped services such as Graph).
    """

    service_name: str = ""
    is_regional = False
    tenant_scoped: bool = False

    async def enumerate(
        self, auth: CloudAuthenticator, scope: Scope
    ) -> ServiceResult:
        assert isinstance(auth, AzureAuthenticator)
        result = ServiceResult(provider=Provider.AZURE, service=self.service_name)
        self._scope = scope  # exposed via :meth:`is_focused_on`

        if self.tenant_scoped:
            try:
                await self.collect_tenant(auth, result)
            except HttpResponseError as exc:
                result.errors.append(f"tenant: {_format_http_error(exc)}")
            except EnumerationError as exc:
                result.errors.append(str(exc))
            except Exception as exc:  # noqa: BLE001
                if _looks_like_graph_error(exc):
                    result.errors.append(f"tenant: {_format_graph_error(exc)}")
                else:
                    result.errors.append(f"tenant: {type(exc).__name__}: {exc}")
            return result

        subs = scope.subscription_ids or [auth.config.subscription_id] if auth.config.subscription_id else scope.subscription_ids
        if not subs:
            result.errors.append("no subscription_ids in scope and none on auth config")
            return result

        async def _one(sub_id: str) -> None:
            try:
                await self.collect_subscription(auth, sub_id, result)
            except HttpResponseError as exc:
                result.errors.append(f"[{sub_id}] {_format_http_error(exc)}")
            except Exception as exc:  # noqa: BLE001
                if _looks_like_graph_error(exc):
                    result.errors.append(f"[{sub_id}] {_format_graph_error(exc)}")
                else:
                    result.errors.append(f"[{sub_id}] {type(exc).__name__}: {exc}")

        await bounded_gather(
            [_one(s) for s in subs if s], max_concurrency=scope.max_concurrency
        )
        return result

    def is_focused_on(self, service_name: str | None = None) -> bool:
        """True when the run should fetch deep-scan data for this service.

        Mirrors :meth:`AwsService.ServiceContext.is_focused_on`. Called
        from within ``collect_subscription`` / ``collect_tenant`` to
        decide whether to invoke medium-cost enrichment calls.
        """
        scope = getattr(self, "_scope", None)
        if scope is None:
            return False
        if scope.deep_scan:
            return True
        target = service_name or self.service_name
        return bool(scope.services) and target in scope.services

    @property
    def scope(self) -> Scope | None:
        """Scope from the current :meth:`enumerate` invocation, if any."""
        return getattr(self, "_scope", None)

    async def collect_subscription(
        self, auth: AzureAuthenticator, subscription_id: str, result: ServiceResult
    ) -> None:
        """Gather resources for one subscription (override for sub-scoped services)."""
        _ = auth, subscription_id, result
        raise NotImplementedError

    async def collect_tenant(
        self, auth: AzureAuthenticator, result: ServiceResult
    ) -> None:
        """Gather tenant-scoped resources (override for tenant-scoped services)."""
        _ = auth, result
        raise NotImplementedError


async def iter_async(pager: Any) -> list[Any]:
    """Drain an Azure async pager into a list."""
    items: list[Any] = []
    async for item in pager:
        items.append(item)
    return items


def extract_identity(resource: Any) -> dict[str, Any] | None:
    """Pull managed-identity info off any ARM resource.

    Most Azure SDK models expose a uniform ``identity`` sub-object with
    ``type`` (``SystemAssigned`` / ``UserAssigned`` / ``SystemAssigned,UserAssigned`` / ``None``),
    ``principal_id`` (system-assigned), and ``user_assigned_identities``
    (dict keyed by the UAMI resource id). We normalise that into a small
    dict that every service can render identically:

    - ``label``: short, table-friendly string (``system`` / ``user(2)`` /
      ``system+user(1)``) or ``None`` if the resource has no identity.
    - ``system_principal_id``: service principal id that other resources'
      role assignments would reference.
    - ``user_assigned``: list of UAMI resource ids.
    """
    ident = getattr(resource, "identity", None)
    if ident is None:
        return None
    raw_type = str(getattr(ident, "type", "") or "")
    normalized = raw_type.replace(" ", "").lower()
    has_system = "systemassigned" in normalized
    uas: dict[str, Any] = dict(getattr(ident, "user_assigned_identities", None) or {})
    uas_ids = list(uas.keys())
    if not has_system and not uas_ids:
        return None
    parts: list[str] = []
    if has_system:
        parts.append("system")
    if uas_ids:
        parts.append(f"user({len(uas_ids)})")
    return {
        "label": "+".join(parts),
        "system_principal_id": getattr(ident, "principal_id", None) if has_system else None,
        "user_assigned": uas_ids,
    }


def attach_identity(row: dict[str, Any], resource: Any) -> None:
    """Populate ``identity`` / ``identity_details`` on a resource row.

    No-op if the resource has no managed identity attached. ``identity``
    is always a short string suitable for table columns; the full
    principal id and user-assigned ids are kept in ``identity_details``
    for the per-resource detail panel.
    """
    info = extract_identity(resource)
    if info is None:
        return
    row["identity"] = info["label"]
    details: dict[str, Any] = {}
    if info["system_principal_id"]:
        details["system_principal_id"] = info["system_principal_id"]
    if info["user_assigned"]:
        details["user_assigned"] = info["user_assigned"]
    if details:
        row["identity_details"] = details


def as_dict(item: Any) -> dict[str, Any]:
    """Convert an Azure SDK model to a plain dict."""
    if hasattr(item, "as_dict"):
        return item.as_dict()  # type: ignore[no-any-return]
    if hasattr(item, "__dict__"):
        return {k: v for k, v in item.__dict__.items() if not k.startswith("_")}
    return dict(item) if isinstance(item, dict) else {"value": str(item)}
