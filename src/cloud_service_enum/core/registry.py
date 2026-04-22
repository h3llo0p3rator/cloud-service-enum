"""Service registry mapping ``(provider, service_name)`` to enumerators.

The registry is populated by each provider package at import time; the
CLI looks the keys up to dispatch the user's requested services.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Generic, TypeVar

from cloud_service_enum.core.enumerator import ServiceEnumerator
from cloud_service_enum.core.models import Provider

T = TypeVar("T", bound=ServiceEnumerator)

EnumFactory = Callable[[], ServiceEnumerator]


class ServiceRegistry(Generic[T]):
    """Simple keyed store of enumerator factories."""

    def __init__(self) -> None:
        self._entries: dict[tuple[Provider, str], EnumFactory] = {}

    def register(
        self, provider: Provider, name: str, factory: EnumFactory
    ) -> EnumFactory:
        key = (provider, name)
        if key in self._entries:
            msg = f"duplicate enumerator for {provider}:{name}"
            raise ValueError(msg)
        self._entries[key] = factory
        return factory

    def get(self, provider: Provider, name: str) -> ServiceEnumerator:
        try:
            return self._entries[(provider, name)]()
        except KeyError as exc:
            raise KeyError(f"no enumerator registered for {provider}:{name}") from exc

    def names(self, provider: Provider) -> list[str]:
        return sorted(n for (p, n) in self._entries if p == provider)


registry: ServiceRegistry[ServiceEnumerator] = ServiceRegistry()
