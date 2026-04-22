"""Automation accounts — runbooks, schedules, credentials, variables.

This is the canonical "attacker-gold" Azure service: runbook bodies are
arbitrary PowerShell or Python that frequently embed shared credentials
or call out to managed identities; credentials and variables are how
operators wire those secrets up. The deep branch surfaces the runbook
content + schedule wiring + credential/variable metadata so a defender
can audit what the automation account would do if compromised.
"""

from __future__ import annotations

from typing import Any

from cloud_service_enum.azure.auth import AzureAuthenticator
from cloud_service_enum.azure.base import AzureService, attach_identity, iter_async
from cloud_service_enum.core.models import ServiceResult
from cloud_service_enum.core.secrets import scan_text


class AutomationService(AzureService):
    service_name = "automation"

    async def collect_subscription(
        self, auth: AzureAuthenticator, subscription_id: str, result: ServiceResult
    ) -> None:
        try:
            from azure.mgmt.automation.aio import AutomationClient
        except ImportError:
            result.errors.append(
                "azure-mgmt-automation is not installed; install the [azure] extra"
            )
            return

        focused = self.is_focused_on()
        secret_scan = bool(self.scope and self.scope.secret_scan)

        async with AutomationClient(auth.credential(), subscription_id) as client:
            accounts = await iter_async(client.automation_account.list())
            for acc in accounts:
                rg = acc.id.split("/")[4]
                acc_row: dict[str, Any] = {
                    "kind": "automation-account",
                    "id": acc.id,
                    "name": acc.name,
                    "location": acc.location,
                    "subscription": subscription_id,
                    "sku": acc.sku.name if acc.sku else None,
                    "state": getattr(acc, "state", None),
                    "public_network_access": getattr(
                        acc, "public_network_access", None
                    ),
                }
                attach_identity(acc_row, acc)
                result.resources.append(acc_row)
                await self._collect_runbooks(
                    client, rg, acc.name, subscription_id, result, focused, secret_scan
                )
                await self._collect_schedules(
                    client, rg, acc.name, subscription_id, result
                )
                await self._collect_credentials(
                    client, rg, acc.name, subscription_id, result
                )
                await self._collect_variables(
                    client, rg, acc.name, subscription_id, result
                )

    async def _collect_runbooks(
        self,
        client: Any,
        rg: str,
        account: str,
        subscription_id: str,
        result: ServiceResult,
        focused: bool,
        secret_scan: bool,
    ) -> None:
        try:
            runbooks = await iter_async(
                client.runbook.list_by_automation_account(rg, account)
            )
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"runbooks {account}: {exc}")
            return
        for rb in runbooks:
            row: dict[str, Any] = {
                "kind": "runbook",
                "id": rb.id,
                "name": rb.name,
                "subscription": subscription_id,
                "account": account,
                "type": getattr(rb, "runbook_type", None),
                "state": getattr(rb, "state", None),
                "log_progress": getattr(rb, "log_progress", None),
                "log_verbose": getattr(rb, "log_verbose", None),
            }
            if focused:
                body = await _fetch_runbook_content(client, rg, account, rb)
                if body:
                    row["script"] = body
                    row["script_language"] = (
                        "python"
                        if (rb.runbook_type or "").lower().startswith("python")
                        else "powershell"
                    )
                    if secret_scan:
                        hits = scan_text(rb.name, body)
                        if hits:
                            row["secrets_found"] = [h.as_dict() for h in hits]
            result.resources.append(row)

    async def _collect_schedules(
        self,
        client: Any,
        rg: str,
        account: str,
        subscription_id: str,
        result: ServiceResult,
    ) -> None:
        try:
            schedules = await iter_async(
                client.schedule.list_by_automation_account(rg, account)
            )
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"schedules {account}: {exc}")
            return
        for s in schedules:
            result.resources.append(
                {
                    "kind": "schedule",
                    "id": s.id,
                    "name": s.name,
                    "subscription": subscription_id,
                    "account": account,
                    "frequency": getattr(s, "frequency", None),
                    "interval": getattr(s, "interval", None),
                    "start_time": getattr(s, "start_time", None),
                    "expiry_time": getattr(s, "expiry_time", None),
                    "next_run": getattr(s, "next_run", None),
                    "is_enabled": getattr(s, "is_enabled", None),
                }
            )

    async def _collect_credentials(
        self,
        client: Any,
        rg: str,
        account: str,
        subscription_id: str,
        result: ServiceResult,
    ) -> None:
        try:
            creds = await iter_async(
                client.credential.list_by_automation_account(rg, account)
            )
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"credentials {account}: {exc}")
            return
        for c in creds:
            result.resources.append(
                {
                    "kind": "credential",
                    "id": c.id,
                    "name": c.name,
                    "subscription": subscription_id,
                    "account": account,
                    "user_name": getattr(c, "user_name", None),
                    "description": getattr(c, "description", None),
                    "creation_time": getattr(c, "creation_time", None),
                    "last_modified_time": getattr(c, "last_modified_time", None),
                }
            )

    async def _collect_variables(
        self,
        client: Any,
        rg: str,
        account: str,
        subscription_id: str,
        result: ServiceResult,
    ) -> None:
        try:
            variables = await iter_async(
                client.variable.list_by_automation_account(rg, account)
            )
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"variables {account}: {exc}")
            return
        for v in variables:
            row: dict[str, Any] = {
                "kind": "variable",
                "id": v.id,
                "name": v.name,
                "subscription": subscription_id,
                "account": account,
                "is_encrypted": getattr(v, "is_encrypted", None),
                "value_preview": _preview(getattr(v, "value", None)),
                "description": getattr(v, "description", None),
                "creation_time": getattr(v, "creation_time", None),
                "last_modified_time": getattr(v, "last_modified_time", None),
            }
            result.resources.append(row)


async def _fetch_runbook_content(
    client: Any, rg: str, account: str, rb: Any
) -> str | None:
    """Return the runbook body as text.

    The management API exposes two content endpoints:

    * ``client.runbook.get_content`` — works for ``Published`` runbooks,
      returns the last-published body.
    * ``client.runbook_draft.get_content`` — works for runbooks in
      ``Edit`` state (and sometimes as a fallback for Published ones).

    Both return an ``AsyncIterator[bytes]`` stream, so we need to drain
    the generator before decoding. We try the published endpoint first
    since it matches the displayed ``state`` for most runbooks, then
    fall back to the draft endpoint if that fails (permission denied,
    404 on new runbooks, etc).
    """
    state = (getattr(rb, "state", "") or "").lower()
    attempts = []
    if state == "edit":
        attempts = [client.runbook_draft.get_content, client.runbook.get_content]
    else:
        attempts = [client.runbook.get_content, client.runbook_draft.get_content]
    for fetch in attempts:
        try:
            stream = await fetch(rg, account, rb.name)
        except Exception:  # noqa: BLE001
            continue
        try:
            decoded = await _drain_stream(stream)
        except Exception:  # noqa: BLE001
            continue
        if decoded:
            return decoded
    return None


async def _drain_stream(stream: Any) -> str:
    """Collect an Azure async byte stream into a decoded string."""
    if isinstance(stream, (bytes, bytearray)):
        return bytes(stream).decode("utf-8", errors="replace")
    if isinstance(stream, str):
        return stream
    chunks: list[bytes] = []
    async for chunk in stream:
        if isinstance(chunk, (bytes, bytearray)):
            chunks.append(bytes(chunk))
        elif isinstance(chunk, str):
            chunks.append(chunk.encode("utf-8", errors="replace"))
    return b"".join(chunks).decode("utf-8", errors="replace")


def _preview(value: Any) -> str | None:
    """Show a 12-char preview of a non-encrypted automation variable.

    Encrypted variables are returned as ``None`` by the management API
    so we only ever preview already-readable plaintext.
    """
    if value is None:
        return None
    text = str(value)
    if len(text) <= 32:
        return text
    return f"{text[:24]}…"
