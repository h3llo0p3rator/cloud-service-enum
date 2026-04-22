"""Cloud Run services."""

from __future__ import annotations

from typing import Any

from cloud_service_enum.core.models import ServiceResult
from cloud_service_enum.gcp.base import GcpService, missing_sdk, safe_list


class CloudRunService(GcpService):
    service_name = "cloudrun"

    def collect_project(
        self, credentials: Any, project_id: str, result: ServiceResult
    ) -> None:
        try:
            from google.cloud import run_v2
        except ImportError:
            missing_sdk(result, "google-cloud-run")
            return
        from cloud_service_enum.core.secrets import scan_mapping

        focused = self.is_focused_on()
        secret_scan = bool(self.scope and self.scope.secret_scan)
        client = run_v2.ServicesClient(credentials=credentials)
        services = safe_list(client.list_services(parent=f"projects/{project_id}/locations/-"))
        public = 0
        for s in services:
            ingress = s.ingress.name if s.ingress else None
            if ingress in {"INGRESS_TRAFFIC_ALL", None}:
                public += 1
            row = {
                "kind": "service",
                "id": s.name,
                "name": s.name.split("/")[-1],
                "project": project_id,
                "location": s.name.split("/")[3],
                "ingress": ingress,
                "uri": s.uri,
                "service_account": s.template.service_account if s.template else None,
                "cpu_throttling": (
                    s.template.containers[0].resources.cpu_idle if s.template and s.template.containers else None
                ),
                "generation": s.generation,
            }
            if focused and s.template:
                env_vars: dict[str, str] = {}
                secret_refs: list[str] = []
                images: list[str] = []
                for c in s.template.containers or []:
                    images.append(c.image)
                    for ev in c.env or []:
                        if ev.value_source and ev.value_source.secret_key_ref:
                            ref = ev.value_source.secret_key_ref
                            secret_refs.append(
                                f"{c.name}.{ev.name}->{ref.secret}/{ref.version or 'latest'}"
                            )
                        else:
                            env_vars[f"{c.name}.{ev.name}"] = ev.value or ""
                if env_vars:
                    row["env_vars"] = env_vars
                    if secret_scan:
                        hits = scan_mapping(s.name, env_vars)
                        if hits:
                            row["secrets_found"] = [h.as_dict() for h in hits]
                if secret_refs:
                    row["secret_refs"] = secret_refs
                row["images"] = images
                try:
                    iam = client.get_iam_policy(request={"resource": s.name})
                    row["role_bindings"] = [
                        {"role": b.role, "members": list(b.members)}
                        for b in iam.bindings
                    ]
                except Exception:  # noqa: BLE001
                    pass
            result.resources.append(row)
        result.cis_fields.setdefault("per_project", {})[project_id] = {
            "service_count": len(services),
            "public_services": public,
        }
