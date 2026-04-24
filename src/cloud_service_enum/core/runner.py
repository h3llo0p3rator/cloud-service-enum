"""High-level orchestration loop shared by every provider CLI command."""

from __future__ import annotations

import time
from datetime import datetime, timezone

from cloud_service_enum.core.auth import CloudAuthenticator
from cloud_service_enum.core.concurrency import ServiceFactory, run_services
from cloud_service_enum.core.display import (
    render_config,
    render_identity,
    render_service,
    render_summary,
)
from cloud_service_enum.core.errors import AuthenticationError
from cloud_service_enum.core.models import EnumerationRun, Provider, Scope, ServiceResult
from cloud_service_enum.core.output import get_console, progress_bar, progress_disabled
from cloud_service_enum.core.registry import registry


async def run_provider(
    provider: Provider,
    auth: CloudAuthenticator,
    scope: Scope,
    *,
    show_progress: bool = True,
) -> EnumerationRun:
    """Run every enumerator selected by ``scope.services`` for one provider."""
    console = get_console()
    start = time.monotonic()
    run_start = datetime.now(timezone.utc)

    try:
        identity = (await auth.test()).model_dump()
    except Exception as exc:
        await auth.close()
        raise AuthenticationError(f"{provider}: {exc}") from exc

    extras: dict[str, object] = {}
    if provider is Provider.AZURE and not scope.subscription_ids:
        try:
            from cloud_service_enum.azure.auth import AzureAuthenticator

            if isinstance(auth, AzureAuthenticator):
                if auth.config.subscription_id:
                    scope.subscription_ids = [auth.config.subscription_id]
                else:
                    discovered = await auth.discover_subscriptions()
                    if discovered:
                        scope.subscription_ids = discovered
                        extras["Discovered subscriptions"] = str(len(discovered))
        except Exception:  # noqa: BLE001
            pass

    render_identity(console, identity)
    render_config(console, provider, scope, extras=extras or None)

    selected = scope.services or registry.names(provider)
    enumerators = [registry.get(provider, name) for name in selected]

    def _wrap(enumer: object) -> ServiceFactory:
        async def _factory() -> ServiceResult:
            svc = await enumer.enumerate(auth, scope)  # type: ignore[attr-defined]
            elapsed = (datetime.now(timezone.utc) - svc.started_at).total_seconds()
            svc.finished_at = datetime.now(timezone.utc)
            svc.duration_s = round(elapsed, 3)
            return svc

        return _factory

    tasks: list[tuple[str, ServiceFactory]] = [(e.service_name, _wrap(e)) for e in enumerators]

    effective_progress = show_progress and not progress_disabled()

    try:
        if effective_progress:
            with progress_bar() as bar:
                task_id = bar.add_task(
                    f"[info]{provider.value}[/info] ({len(tasks)} services)",
                    total=len(tasks),
                )

                def _tick(_: ServiceResult) -> None:
                    bar.advance(task_id)

                results = await run_services(
                    tasks,
                    provider=provider,
                    max_concurrency=scope.max_concurrency,
                    timeout=scope.timeout_s,
                    on_done=_tick,
                )
        else:
            results = await run_services(
                tasks,
                provider=provider,
                max_concurrency=scope.max_concurrency,
                timeout=scope.timeout_s,
            )
    finally:
        await auth.close()

    duration = round(time.monotonic() - start, 3)
    sorted_results = sorted(results, key=lambda s: s.service)
    run = EnumerationRun(
        provider=provider,
        scope=scope,
        identity=identity,
        services=sorted_results,
        started_at=run_start,
        finished_at=datetime.now(timezone.utc),
        duration_s=duration,
    )

    for svc in sorted_results:
        render_service(console, svc)
    render_summary(console, run)

    return run
