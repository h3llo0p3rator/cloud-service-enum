"""Register every AWS service enumerator with the global registry."""

from __future__ import annotations

from cloud_service_enum.aws.services.acm import AcmService
from cloud_service_enum.aws.services.cloudformation import CloudFormationService
from cloud_service_enum.aws.services.cloudfront import CloudFrontService
from cloud_service_enum.aws.services.cloudtrail import CloudTrailService
from cloud_service_enum.aws.services.cloudwatch import CloudWatchService
from cloud_service_enum.aws.services.config import ConfigService
from cloud_service_enum.aws.services.dynamodb import DynamoDbService
from cloud_service_enum.aws.services.ec2 import Ec2Service
from cloud_service_enum.aws.services.efs import EfsService
from cloud_service_enum.aws.services.eks import EksService
from cloud_service_enum.aws.services.elasticache import ElastiCacheService
from cloud_service_enum.aws.services.glue import GlueService
from cloud_service_enum.aws.services.guardduty import GuardDutyService
from cloud_service_enum.aws.services.iam import IamService
from cloud_service_enum.aws.services.inspector import InspectorService
from cloud_service_enum.aws.services.kinesis import KinesisService
from cloud_service_enum.aws.services.kms import KmsService
from cloud_service_enum.aws.services.lambda_ import LambdaService
from cloud_service_enum.aws.services.macie import MacieService
from cloud_service_enum.aws.services.msk import MskService
from cloud_service_enum.aws.services.opensearch import OpenSearchService
from cloud_service_enum.aws.services.organizations import OrganizationsService
from cloud_service_enum.aws.services.rds import RdsService
from cloud_service_enum.aws.services.redshift import RedshiftService
from cloud_service_enum.aws.services.route53 import Route53Service
from cloud_service_enum.aws.services.s3 import S3Service
from cloud_service_enum.aws.services.secretsmanager import SecretsManagerService
from cloud_service_enum.aws.services.securityhub import SecurityHubService
from cloud_service_enum.aws.services.sns import SnsService
from cloud_service_enum.aws.services.sqs import SqsService
from cloud_service_enum.aws.services.stepfunctions import StepFunctionsService
from cloud_service_enum.aws.services.sts import StsService
from cloud_service_enum.aws.services.vpc import VpcService
from cloud_service_enum.aws.services.wafv2 import WafV2Service
from cloud_service_enum.core.models import Provider
from cloud_service_enum.core.registry import registry

_SERVICES = [
    AcmService,
    CloudFormationService,
    CloudFrontService,
    CloudTrailService,
    CloudWatchService,
    ConfigService,
    DynamoDbService,
    Ec2Service,
    EfsService,
    EksService,
    ElastiCacheService,
    GlueService,
    GuardDutyService,
    IamService,
    InspectorService,
    KinesisService,
    KmsService,
    LambdaService,
    MacieService,
    MskService,
    OpenSearchService,
    OrganizationsService,
    RdsService,
    RedshiftService,
    Route53Service,
    S3Service,
    SecretsManagerService,
    SecurityHubService,
    SnsService,
    SqsService,
    StepFunctionsService,
    StsService,
    VpcService,
    WafV2Service,
]

for _cls in _SERVICES:
    registry.register(Provider.AWS, _cls.service_name, _cls)
