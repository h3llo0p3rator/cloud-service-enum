"""Cloud DNS managed zones and DNSSEC posture."""

from __future__ import annotations

from typing import Any

from cloud_service_enum.core.models import ServiceResult
from cloud_service_enum.gcp.base import GcpService, missing_sdk


class DnsService(GcpService):
    service_name = "dns"

    def collect_project(
        self, credentials: Any, project_id: str, result: ServiceResult
    ) -> None:
        try:
            from google.cloud import dns
        except ImportError:
            missing_sdk(result, "google-cloud-dns")
            return
        client = dns.Client(project=project_id, credentials=credentials)
        zones = list(client.list_zones())
        dnssec_enabled = 0
        focused = self.is_focused_on()
        for z in zones:
            dnssec = z.dnssec_config
            enabled = bool(dnssec and getattr(dnssec, "state", None) == "on")
            if enabled:
                dnssec_enabled += 1
            row = {
                "kind": "managed-zone",
                "id": z.name,
                "name": z.dns_name,
                "project": project_id,
                "description": z.description,
                "visibility": z.visibility,
                "dnssec_enabled": enabled,
            }
            if focused:
                try:
                    records = list(z.list_resource_record_sets(max_results=200))
                    row["records"] = [
                        {
                            "name": r.name,
                            "type": r.record_type,
                            "ttl": r.ttl,
                            "rrdatas": list(r.rrdatas)[:5],
                        }
                        for r in records
                    ]
                except Exception:  # noqa: BLE001
                    pass
            result.resources.append(row)
        result.cis_fields.setdefault("per_project", {})[project_id] = {
            "zone_count": len(zones),
            "zones_with_dnssec": dnssec_enabled,
        }
