"""Register every Azure service enumerator with the global registry."""

from __future__ import annotations

from cloud_service_enum.azure.services.administrative_units import (
    AdministrativeUnitsService,
)
from cloud_service_enum.azure.services.aks import AksService
from cloud_service_enum.azure.services.apim import ApimService
from cloud_service_enum.azure.services.app_registrations import (
    AppRegistrationsService,
)
from cloud_service_enum.azure.services.appgateway import AppGatewayService
from cloud_service_enum.azure.services.appservice import AppServiceService
from cloud_service_enum.azure.services.arc import ArcService
from cloud_service_enum.azure.services.automation import AutomationService
from cloud_service_enum.azure.services.bastion import BastionService
from cloud_service_enum.azure.services.compute import ComputeService
from cloud_service_enum.azure.services.conditional_access import ConditionalAccessService
from cloud_service_enum.azure.services.containerapps import ContainerAppsService
from cloud_service_enum.azure.services.containerregistry import ContainerRegistryService
from cloud_service_enum.azure.services.cosmosdb import CosmosDbService
from cloud_service_enum.azure.services.defender import DefenderService
from cloud_service_enum.azure.services.devops import DevOpsService
from cloud_service_enum.azure.services.eventgrid import EventGridService
from cloud_service_enum.azure.services.eventhubs import EventHubsService
from cloud_service_enum.azure.services.firewall import FirewallService
from cloud_service_enum.azure.services.frontdoor import FrontDoorService
from cloud_service_enum.azure.services.graph import GraphService
from cloud_service_enum.azure.services.keyvault import KeyVaultService
from cloud_service_enum.azure.services.loganalytics import LogAnalyticsService
from cloud_service_enum.azure.services.logicapps import LogicAppsService
from cloud_service_enum.azure.services.managed_identity import (
    ManagedIdentityService,
)
from cloud_service_enum.azure.services.monitor import MonitorService
from cloud_service_enum.azure.services.network import NetworkService
from cloud_service_enum.azure.services.pim import PimService
from cloud_service_enum.azure.services.policy import PolicyService
from cloud_service_enum.azure.services.policyinsights import PolicyInsightsService
from cloud_service_enum.azure.services.postgresql import PostgresqlService
from cloud_service_enum.azure.services.rbac import RbacService
from cloud_service_enum.azure.services.resources import ResourcesService
from cloud_service_enum.azure.services.sentinel import SentinelService
from cloud_service_enum.azure.services.servicebus import ServiceBusService
from cloud_service_enum.azure.services.sql import SqlService
from cloud_service_enum.azure.services.storage import StorageService
from cloud_service_enum.azure.services.subscriptions import SubscriptionsService
from cloud_service_enum.core.models import Provider
from cloud_service_enum.core.registry import registry

_SERVICES = [
    AdministrativeUnitsService,
    AksService,
    ApimService,
    AppGatewayService,
    AppRegistrationsService,
    AppServiceService,
    ArcService,
    AutomationService,
    BastionService,
    ComputeService,
    ConditionalAccessService,
    ContainerAppsService,
    ContainerRegistryService,
    CosmosDbService,
    DefenderService,
    DevOpsService,
    EventGridService,
    EventHubsService,
    FirewallService,
    FrontDoorService,
    GraphService,
    KeyVaultService,
    LogAnalyticsService,
    LogicAppsService,
    ManagedIdentityService,
    MonitorService,
    NetworkService,
    PimService,
    PolicyService,
    PolicyInsightsService,
    PostgresqlService,
    RbacService,
    ResourcesService,
    SentinelService,
    ServiceBusService,
    SqlService,
    StorageService,
    SubscriptionsService,
]

for _cls in _SERVICES:
    registry.register(Provider.AZURE, _cls.service_name, _cls)
