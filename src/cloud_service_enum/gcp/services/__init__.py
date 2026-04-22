"""Register every GCP service enumerator with the global registry."""

from __future__ import annotations

from cloud_service_enum.core.models import Provider
from cloud_service_enum.core.registry import registry

from cloud_service_enum.gcp.services.bigquery import BigQueryService
from cloud_service_enum.gcp.services.binaryauthorization import BinaryAuthorizationService
from cloud_service_enum.gcp.services.cloudarmor import CloudArmorService
from cloud_service_enum.gcp.services.cloudfunctions import CloudFunctionsService
from cloud_service_enum.gcp.services.cloudrun import CloudRunService
from cloud_service_enum.gcp.services.cloudsql import CloudSqlService
from cloud_service_enum.gcp.services.compute import ComputeService
from cloud_service_enum.gcp.services.dns import DnsService
from cloud_service_enum.gcp.services.firestore import FirestoreService
from cloud_service_enum.gcp.services.gke import GkeService
from cloud_service_enum.gcp.services.iam import IamService
from cloud_service_enum.gcp.services.iap import IapService
from cloud_service_enum.gcp.services.kms import KmsService
from cloud_service_enum.gcp.services.logging import LoggingService
from cloud_service_enum.gcp.services.memorystore import MemorystoreService
from cloud_service_enum.gcp.services.monitoring import MonitoringService
from cloud_service_enum.gcp.services.project import ProjectService
from cloud_service_enum.gcp.services.pubsub import PubSubService
from cloud_service_enum.gcp.services.secretmanager import SecretManagerService
from cloud_service_enum.gcp.services.securitycenter import SecurityCenterService
from cloud_service_enum.gcp.services.spanner import SpannerService
from cloud_service_enum.gcp.services.storage import StorageService
from cloud_service_enum.gcp.services.vertexai import VertexAiService
from cloud_service_enum.gcp.services.vpc import VpcService

_SERVICES = [
    BigQueryService,
    BinaryAuthorizationService,
    CloudArmorService,
    CloudFunctionsService,
    CloudRunService,
    CloudSqlService,
    ComputeService,
    DnsService,
    FirestoreService,
    GkeService,
    IamService,
    IapService,
    KmsService,
    LoggingService,
    MemorystoreService,
    MonitoringService,
    ProjectService,
    PubSubService,
    SecretManagerService,
    SecurityCenterService,
    SpannerService,
    StorageService,
    VertexAiService,
    VpcService,
]

for _cls in _SERVICES:
    registry.register(Provider.GCP, _cls.service_name, _cls)
