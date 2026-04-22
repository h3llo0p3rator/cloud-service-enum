"""Cloud Functions (gen 2)."""

from __future__ import annotations

from typing import Any

from cloud_service_enum.core.models import ServiceResult
from cloud_service_enum.gcp.base import GcpService, missing_sdk, safe_list


class CloudFunctionsService(GcpService):
    service_name = "cloudfunctions"

    def collect_project(
        self, credentials: Any, project_id: str, result: ServiceResult
    ) -> None:
        try:
            from google.cloud import functions_v2
        except ImportError:
            missing_sdk(result, "google-cloud-functions")
            return
        from cloud_service_enum.core.secrets import scan_mapping

        focused = self.is_focused_on()
        secret_scan = bool(self.scope and self.scope.secret_scan)
        client = functions_v2.FunctionServiceClient(credentials=credentials)
        fns = safe_list(client.list_functions(parent=f"projects/{project_id}/locations/-"))
        for f in fns:
            service_config = f.service_config
            row = {
                "kind": "function",
                "id": f.name,
                "name": f.name.split("/")[-1],
                "project": project_id,
                "location": f.name.split("/")[3],
                "environment": f.environment.name,
                "state": f.state.name,
                "runtime": f.build_config.runtime if f.build_config else None,
                "entry_point": f.build_config.entry_point if f.build_config else None,
                "service_account": service_config.service_account_email if service_config else None,
                "ingress": service_config.ingress_settings.name if service_config else None,
                "vpc_connector": service_config.vpc_connector if service_config else None,
                "min_instances": service_config.min_instance_count if service_config else None,
                "max_instances": service_config.max_instance_count if service_config else None,
            }
            if focused and service_config:
                env_vars = dict(service_config.environment_variables or {})
                if env_vars:
                    row["env_vars"] = env_vars
                    if secret_scan:
                        hits = scan_mapping(f.name, env_vars)
                        if hits:
                            row["secrets_found"] = [h.as_dict() for h in hits]
                row["secret_environment_variables"] = [
                    {
                        "key": s.key,
                        "project_id": s.project_id,
                        "secret": s.secret,
                        "version": s.version,
                    }
                    for s in service_config.secret_environment_variables or []
                ]
                if f.build_config and f.build_config.source:
                    src = f.build_config.source
                    storage = getattr(src, "storage_source", None)
                    if storage:
                        row["source_archive"] = (
                            f"gs://{storage.bucket}/{storage.object_}"
                            if storage.bucket
                            else None
                        )
                try:
                    iam = client.get_iam_policy(request={"resource": f.name})
                    row["role_bindings"] = [
                        {"role": b.role, "members": list(b.members)}
                        for b in iam.bindings
                    ]
                except Exception:  # noqa: BLE001
                    pass
            result.resources.append(row)
        result.cis_fields.setdefault("per_project", {})[project_id] = {
            "function_count": len(fns),
            "internal_only_functions": sum(
                1
                for f in fns
                if f.service_config and f.service_config.ingress_settings.name == "ALLOW_INTERNAL_ONLY"
            ),
        }
