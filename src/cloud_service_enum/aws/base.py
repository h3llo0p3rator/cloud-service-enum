"""Shared base class for every AWS service enumerator."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from cloud_service_enum.aws.auth import AwsAuthenticator
from cloud_service_enum.core.auth import CloudAuthenticator
from cloud_service_enum.core.concurrency import bounded_gather
from cloud_service_enum.core.models import Provider, Scope, ServiceResult


class AwsService(ABC):
    """Base class shared by every AWS service enumerator.

    ``is_regional`` services are fanned out across every region in
    ``scope.regions`` (or, if unset, every enabled region in the
    account); global services are invoked once.
    """

    service_name: str = ""
    is_regional: bool = True
    default_region: str = "us-east-1"

    async def enumerate(
        self, auth: CloudAuthenticator, scope: Scope
    ) -> ServiceResult:
        assert isinstance(auth, AwsAuthenticator)
        result = ServiceResult(provider=Provider.AWS, service=self.service_name)

        regions: list[str]
        if self.is_regional:
            regions = scope.regions or await self._safe_list_regions(auth)
        else:
            regions = [scope.regions[0] if scope.regions else self.default_region]

        session = await auth.session()

        async def _one(region: str) -> None:
            try:
                await self.collect(
                    ServiceContext(session=session, region=region, scope=scope), result
                )
            except (ClientError, BotoCoreError) as exc:
                result.errors.append(f"[{region}] {type(exc).__name__}: {exc}")
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"[{region}] {type(exc).__name__}: {exc}")

        if self.is_regional:
            await bounded_gather(
                [_one(r) for r in regions], max_concurrency=scope.max_concurrency
            )
        else:
            await _one(regions[0])
        return result

    async def _safe_list_regions(self, auth: AwsAuthenticator) -> list[str]:
        try:
            return await auth.list_regions()
        except Exception:  # noqa: BLE001
            return [auth.config.region or self.default_region]

    @abstractmethod
    async def collect(self, ctx: ServiceContext, result: ServiceResult) -> None:
        """Populate ``result.resources`` / ``result.cis_fields`` for one region."""


class ServiceContext:
    """Per-region context passed into :meth:`AwsService.collect`.

    Provides a helper :meth:`client` that yields async boto3 clients on
    demand so a single service can talk to several APIs (e.g. CloudWatch
    and CloudWatch Logs).
    """

    def __init__(self, *, session: Any, region: str, scope: Scope) -> None:
        self.session = session
        self.region = region
        self.scope = scope

    @asynccontextmanager
    async def client(self, name: str) -> AsyncIterator[Any]:
        async with self.session.client(name, region_name=self.region) as c:
            yield c

    def is_focused_on(self, service_name: str) -> bool:
        """True when the run should fetch deep-scan data for ``service_name``.

        Deep mode is enabled when the user either sets ``--deep`` globally
        or restricts the run to a single service that matches (or any
        service list that contains ``service_name``). Broad runs without
        an explicit service filter stay in shallow/metadata-only mode.
        """
        if self.scope.deep_scan:
            return True
        return bool(self.scope.services) and service_name in self.scope.services


async def paginate(client: Any, operation: str, **kwargs: Any) -> list[dict[str, Any]]:
    """Consume a boto paginator and return the raw page list."""
    paginator = client.get_paginator(operation)
    pages: list[dict[str, Any]] = []
    async for page in paginator.paginate(**kwargs):
        pages.append(page)
    return pages


def collect_items(pages: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    """Flatten a list-valued key across paginator pages."""
    out: list[dict[str, Any]] = []
    for page in pages:
        out.extend(page.get(key, []) or [])
    return out


async def safe(awaitable: Any) -> Any:
    """Await ``awaitable`` and return ``None`` on failure."""
    try:
        return await awaitable
    except Exception:  # noqa: BLE001
        return None
