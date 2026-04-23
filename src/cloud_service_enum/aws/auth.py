"""Async AWS authenticator supporting every common credential method."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import aioboto3
from botocore.exceptions import BotoCoreError, ClientError

from cloud_service_enum.core.auth import CloudAuthenticator, IdentitySummary
from cloud_service_enum.core.errors import AuthenticationError

# Canonical region list used when ``ec2:DescribeRegions`` is unavailable
# (e.g. scoped instance roles that can still do IAM/STS/Org work). Covers
# the regions where an attacker-relevant service is most likely to exist
# without pulling in opt-in regions that would require explicit account
# enablement.
FALLBACK_REGIONS: tuple[str, ...] = (
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "eu-west-1",
    "eu-west-2",
    "eu-central-1",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-northeast-1",
)


@dataclass
class AwsAuthConfig:
    """Inputs describing how to build an AWS session.

    Only one of the mutually-exclusive inputs needs to be set; if none
    are provided the boto default credential chain is used.
    """

    profile: str | None = None
    region: str | None = None
    access_key: str | None = None
    secret_key: str | None = None
    session_token: str | None = None
    role_arn: str | None = None
    role_session_name: str = "cloud-service-enum"
    external_id: str | None = None
    mfa_serial: str | None = None
    mfa_token: str | None = None
    web_identity_token_file: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


class AwsAuthenticator(CloudAuthenticator):
    """aioboto3-backed authenticator usable by every AWS enumerator."""

    provider = "aws"

    def __init__(self, config: AwsAuthConfig | None = None) -> None:
        self.config = config or AwsAuthConfig()
        self._session: aioboto3.Session | None = None
        self._sts_cache: dict[str, str] | None = None

    async def _build_session(self) -> aioboto3.Session:
        kwargs: dict[str, Any] = {}
        if self.config.profile:
            kwargs["profile_name"] = self.config.profile
        if self.config.region:
            kwargs["region_name"] = self.config.region
        if self.config.access_key and self.config.secret_key:
            kwargs["aws_access_key_id"] = self.config.access_key
            kwargs["aws_secret_access_key"] = self.config.secret_key
            if self.config.session_token:
                kwargs["aws_session_token"] = self.config.session_token

        session = aioboto3.Session(**kwargs)

        if self.config.role_arn:
            session = await self._assume_role(session)
        return session

    async def _assume_role(self, base: aioboto3.Session) -> aioboto3.Session:
        assume_kwargs: dict[str, Any] = {
            "RoleArn": self.config.role_arn,
            "RoleSessionName": self.config.role_session_name,
        }
        if self.config.external_id:
            assume_kwargs["ExternalId"] = self.config.external_id
        if self.config.mfa_serial and self.config.mfa_token:
            assume_kwargs["SerialNumber"] = self.config.mfa_serial
            assume_kwargs["TokenCode"] = self.config.mfa_token

        async with base.client("sts") as sts:
            if self.config.web_identity_token_file:
                token = open(self.config.web_identity_token_file).read()
                resp = await sts.assume_role_with_web_identity(
                    RoleArn=self.config.role_arn,
                    RoleSessionName=self.config.role_session_name,
                    WebIdentityToken=token,
                )
            else:
                resp = await sts.assume_role(**assume_kwargs)

        creds = resp["Credentials"]
        return aioboto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=self.config.region,
        )

    async def session(self) -> aioboto3.Session:
        if self._session is None:
            self._session = await self._build_session()
        return self._session

    async def test(self) -> IdentitySummary:
        session = await self.session()
        try:
            async with session.client("sts") as sts:
                ident = await sts.get_caller_identity()
        except (ClientError, BotoCoreError) as exc:
            raise AuthenticationError(f"STS GetCallerIdentity failed: {exc}") from exc

        self._sts_cache = {
            "Account": ident["Account"],
            "Arn": ident["Arn"],
            "UserId": ident["UserId"],
        }
        method = "role-assumption" if self.config.role_arn else (
            "profile" if self.config.profile else (
                "static-keys" if self.config.access_key else "default-chain"
            )
        )
        return IdentitySummary(
            provider="aws",
            principal=ident["Arn"],
            display_name=ident["UserId"],
            tenant_or_account=ident["Account"],
            auth_method=method,
        )

    async def list_regions(self) -> list[str]:
        """Return every region enabled on the account.

        Requires ``ec2:DescribeRegions``. Callers that want graceful
        degradation (scoped roles often lack this permission) should wrap
        this call and substitute :data:`FALLBACK_REGIONS` on failure.
        """
        session = await self.session()
        region = self.config.region or session.region_name or "us-east-1"
        async with session.client("ec2", region_name=region) as ec2:
            resp = await ec2.describe_regions(AllRegions=False)
        return sorted(r["RegionName"] for r in resp["Regions"])

    @property
    def account_id(self) -> str | None:
        return self._sts_cache["Account"] if self._sts_cache else None

    async def close(self) -> None:
        self._session = None
