"""Arc / HybridCompute — machines, extensions, run-command metadata.

Arc-enrolled machines are on-prem boxes with an Azure control plane; the
Arc agent accepts ``RunCommand`` invocations whose output lands in a
blob URL. That URL is the single most attacker-relevant artefact so the
service surfaces it without downloading the body — operators decide
whether to pull content separately.
"""

from __future__ import annotations

from typing import Any

from cloud_service_enum.azure.auth import AzureAuthenticator
from cloud_service_enum.azure.base import AzureService, attach_identity, iter_async
from cloud_service_enum.core.models import ServiceResult


class ArcService(AzureService):
    service_name = "arc"

    async def collect_subscription(
        self, auth: AzureAuthenticator, subscription_id: str, result: ServiceResult
    ) -> None:
        try:
            from azure.mgmt.hybridcompute.aio import HybridComputeManagementClient
        except ImportError:
            result.errors.append(
                "azure-mgmt-hybridcompute is not installed; install the [azure] extra"
            )
            return

        focused = self.is_focused_on()
        async with HybridComputeManagementClient(
            auth.credential(), subscription_id
        ) as client:
            supports_run_commands = hasattr(client, "machine_run_commands")
            machines = await iter_async(client.machines.list_by_subscription())
            for machine in machines:
                rg = (machine.id or "").split("/")[4] if machine.id else None
                row = _machine_row(machine, subscription_id, rg)
                attach_identity(row, machine)
                result.resources.append(row)
                if not rg or not machine.name:
                    continue
                await _collect_extensions(
                    client, rg, machine.name, subscription_id, result
                )
                if focused and supports_run_commands:
                    await _collect_run_commands(
                        client, rg, machine.name, subscription_id, result
                    )

        result.cis_fields.setdefault("per_subscription", {})[subscription_id] = {
            "machine_count": len(machines),
            "disconnected": sum(
                1 for m in machines if (getattr(m, "status", "") or "").lower() != "connected"
            ),
            "run_command_metadata_supported": supports_run_commands,
        }


def _machine_row(
    machine: Any, subscription_id: str, rg: str | None
) -> dict[str, Any]:
    os_profile = getattr(machine, "os_profile", None)
    agent_config = getattr(machine, "agent_configuration", None)
    return {
        "kind": "arc-machine",
        "id": machine.id,
        "name": machine.name,
        "resource_group": rg,
        "location": getattr(machine, "location", None),
        "subscription": subscription_id,
        "os_name": getattr(machine, "os_name", None),
        "os_version": getattr(machine, "os_version", None),
        "os_type": getattr(machine, "os_type", None),
        "status": getattr(machine, "status", None),
        "last_status_change": getattr(machine, "last_status_change", None),
        "agent_version": getattr(machine, "agent_version", None),
        "agent_proxy_bypass": getattr(agent_config, "proxy_bypass", None)
        if agent_config
        else None,
        "ad_fqdn": getattr(machine, "ad_fqdn", None),
        "dns_fqdn": getattr(machine, "dns_fqdn", None),
        "domain_name": getattr(machine, "domain_name", None),
        "machine_fqdn": getattr(machine, "machine_fqdn", None),
        "display_name": getattr(machine, "display_name", None)
        or (getattr(os_profile, "computer_name", None) if os_profile else None),
        "vm_id": getattr(machine, "vm_id", None),
    }


async def _collect_extensions(
    client: Any,
    rg: str,
    machine_name: str,
    subscription_id: str,
    result: ServiceResult,
) -> None:
    try:
        extensions = await iter_async(
            client.machine_extensions.list(rg, machine_name)
        )
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"arc-extensions {machine_name}: {exc}")
        return
    for ext in extensions:
        props = getattr(ext, "properties", None) or ext
        result.resources.append(
            {
                "kind": "arc-extension",
                "id": ext.id,
                "name": ext.name,
                "resource_group": rg,
                "machine": machine_name,
                "subscription": subscription_id,
                "publisher": getattr(props, "publisher", None),
                "type": getattr(props, "type_properties_type", None)
                or getattr(props, "type", None),
                "version": getattr(props, "type_handler_version", None),
                "provisioning_state": getattr(props, "provisioning_state", None),
                "auto_upgrade_minor_version": getattr(
                    props, "auto_upgrade_minor_version", None
                ),
                "enable_automatic_upgrade": getattr(
                    props, "enable_automatic_upgrade", None
                ),
                "settings": getattr(props, "settings", None),
            }
        )


async def _collect_run_commands(
    client: Any,
    rg: str,
    machine_name: str,
    subscription_id: str,
    result: ServiceResult,
) -> None:
    try:
        commands = await iter_async(
            client.machine_run_commands.list(rg, machine_name)
        )
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"arc-run-commands {machine_name}: {exc}")
        return
    for cmd in commands:
        instance = getattr(cmd, "instance_view", None)
        output_uri = None
        script_uri = None
        source = getattr(cmd, "source", None)
        if source is not None:
            script_uri = (
                getattr(source, "script_uri", None)
                or getattr(source, "command_id", None)
            )
        if hasattr(cmd, "output_blob_uri"):
            output_uri = cmd.output_blob_uri
        error_uri = getattr(cmd, "error_blob_uri", None)
        result.resources.append(
            {
                "kind": "arc-run-command",
                "id": cmd.id,
                "name": cmd.name,
                "resource_group": rg,
                "machine": machine_name,
                "subscription": subscription_id,
                "provisioning_state": getattr(cmd, "provisioning_state", None),
                "async_execution": getattr(cmd, "async_execution", None),
                "run_as_user": getattr(cmd, "run_as_user", None),
                "timeout_seconds": getattr(cmd, "timeout_in_seconds", None),
                "script_uri": script_uri,
                "output_blob_uri": output_uri,
                "error_blob_uri": error_uri,
                "exit_code": getattr(instance, "exit_code", None) if instance else None,
                "execution_state": getattr(instance, "execution_state", None)
                if instance
                else None,
                "start_time": getattr(instance, "start_time", None)
                if instance
                else None,
                "end_time": getattr(instance, "end_time", None)
                if instance
                else None,
            }
        )
