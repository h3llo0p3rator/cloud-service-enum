"""App Service Web Apps, Function Apps and App Service Plans."""

from __future__ import annotations

from azure.mgmt.web.aio import WebSiteManagementClient

from cloud_service_enum.azure.auth import AzureAuthenticator
from cloud_service_enum.azure.base import AzureService, attach_identity, iter_async
from cloud_service_enum.core.models import ServiceResult


class AppServiceService(AzureService):
    service_name = "appservice"

    async def collect_subscription(
        self, auth: AzureAuthenticator, subscription_id: str, result: ServiceResult
    ) -> None:
        focused = self.is_focused_on()
        secret_scan = bool(self.scope and self.scope.secret_scan)
        async with WebSiteManagementClient(auth.credential(), subscription_id) as client:
            sites = await iter_async(client.web_apps.list())
            plans = await iter_async(client.app_service_plans.list())
            for s in sites:
                row = {
                    "kind": "web-app",
                    "id": s.id,
                    "name": s.name,
                    "location": s.location,
                    "subscription": subscription_id,
                    "kind_class": s.kind,
                    "https_only": s.https_only,
                    "state": s.state,
                    "host_names": s.host_names,
                    "default_host_name": s.default_host_name,
                    "client_cert_enabled": s.client_cert_enabled,
                    "client_cert_mode": s.client_cert_mode,
                    "public_network_access": s.public_network_access,
                }
                attach_identity(row, s)
                if focused:
                    rg = s.id.split("/")[4]
                    await self._enrich(client, rg, s.name, row, secret_scan)
                result.resources.append(row)
        for p in plans:
            result.resources.append(
                {
                    "kind": "plan",
                    "id": p.id,
                    "name": p.name,
                    "location": p.location,
                    "subscription": subscription_id,
                    "sku": p.sku.name if p.sku else None,
                    "worker_count": p.number_of_workers,
                }
            )
        result.cis_fields.setdefault("per_subscription", {})[subscription_id] = {
            "site_count": len(sites),
            "plan_count": len(plans),
            "sites_without_https_only": sum(1 for s in sites if not s.https_only),
        }

    @staticmethod
    async def _enrich(
        client: WebSiteManagementClient,
        rg: str,
        name: str,
        row: dict,
        secret_scan: bool,
    ) -> None:
        from cloud_service_enum.core.secrets import scan_mapping

        try:
            settings = await client.web_apps.list_application_settings(rg, name)
            props = dict(settings.properties or {})
            if props:
                row["app_settings"] = props
                if secret_scan:
                    hits = scan_mapping(name, props)
                    if hits:
                        row["secrets_found"] = [h.as_dict() for h in hits]
        except Exception:  # noqa: BLE001
            pass
        try:
            conns = await client.web_apps.list_connection_strings(rg, name)
            cs_props = dict(conns.properties or {})
            if cs_props:
                row["connection_strings"] = {
                    k: v.value if hasattr(v, "value") else str(v)
                    for k, v in cs_props.items()
                }
        except Exception:  # noqa: BLE001
            pass
        try:
            auth = await client.web_apps.get_auth_settings_v2(rg, name)
            if auth:
                row["auth_settings"] = auth.as_dict() if hasattr(auth, "as_dict") else None
        except Exception:  # noqa: BLE001
            pass
        try:
            cfg = await client.web_apps.get_configuration(rg, name)
            if cfg:
                row["site_config"] = {
                    "linux_fx_version": getattr(cfg, "linux_fx_version", None),
                    "windows_fx_version": getattr(cfg, "windows_fx_version", None),
                    "ftps_state": getattr(cfg, "ftps_state", None),
                    "min_tls_version": getattr(cfg, "min_tls_version", None),
                    "remote_debugging": getattr(cfg, "remote_debugging_enabled", None),
                    "scm_ip_security_restrictions": [
                        r.as_dict() if hasattr(r, "as_dict") else str(r)
                        for r in getattr(cfg, "scm_ip_security_restrictions", None) or []
                    ],
                }
        except Exception:  # noqa: BLE001
            pass
