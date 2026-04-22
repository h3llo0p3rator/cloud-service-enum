"""Structured-concurrency helpers built on :class:`asyncio.TaskGroup`.

All fan-out in the codebase flows through this module so retry, timeout
and semaphore policies stay in one place.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import TypeVar

from cloud_service_enum.core.errors import EnumerationError
from cloud_service_enum.core.models import Provider, ServiceResult

T = TypeVar("T")

ServiceFactory = Callable[[], Awaitable[ServiceResult]]


async def _guarded(
    sem: asyncio.Semaphore, coro: Awaitable[T], *, timeout: float | None = None
) -> T:
    async with sem:
        if timeout is None:
            return await coro
        return await asyncio.wait_for(coro, timeout=timeout)


async def bounded_gather(
    coros: list[Awaitable[T]],
    *,
    max_concurrency: int = 10,
    timeout: float | None = None,
    return_exceptions: bool = False,
) -> list[T | BaseException]:
    """Run many coroutines with a shared semaphore."""
    sem = asyncio.Semaphore(max(1, max_concurrency))
    tasks = [_guarded(sem, c, timeout=timeout) for c in coros]
    return await asyncio.gather(*tasks, return_exceptions=return_exceptions)


async def run_services(
    tasks: list[tuple[str, ServiceFactory]],
    *,
    provider: Provider,
    max_concurrency: int = 10,
    timeout: float | None = 120.0,
    on_done: Callable[[ServiceResult], None] | None = None,
) -> list[ServiceResult]:
    """Run many service enumerators concurrently.

    Failures are captured as a :class:`ServiceResult` with the exception
    message in ``errors`` so the caller never has to handle exceptions.
    """
    sem = asyncio.Semaphore(max(1, max_concurrency))
    results: list[ServiceResult] = []

    async def _run(name: str, factory: ServiceFactory) -> None:
        try:
            res = await _guarded(sem, factory(), timeout=timeout)
        except TimeoutError:
            res = ServiceResult(provider=provider, service=name, errors=[f"timeout after {timeout}s"])
        except EnumerationError as exc:
            res = ServiceResult(provider=provider, service=name, errors=[str(exc)])
        except Exception as exc:  # noqa: BLE001 - last-resort guard
            res = ServiceResult(provider=provider, service=name, errors=[repr(exc)])
        results.append(res)
        if on_done is not None:
            on_done(res)

    async with asyncio.TaskGroup() as tg:
        for name, factory in tasks:
            tg.create_task(_run(name, factory))
    return results
