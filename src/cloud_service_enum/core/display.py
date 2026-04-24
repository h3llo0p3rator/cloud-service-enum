"""Terminal rendering helpers used by the runner and OSINT entry point.

Everything here is Rich-only and side-effect-free apart from printing to
the supplied :class:`~rich.console.Console`. The intent is to give the
user a useful at-a-glance view of every run while leaving the JSON/XLSX
report as the source of truth.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from datetime import date, datetime
from typing import Any

from rich.box import SIMPLE_HEAVY
from rich.markup import escape as _escape_markup
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from cloud_service_enum.core.models import EnumerationRun, Provider, Scope, ServiceResult
from cloud_service_enum.core.output import Console

_PREFERRED_COLUMNS: tuple[str, ...] = (
    "kind",
    "id",
    "arn",
    "name",
    "region",
    "identity",
    "impersonators",
    # Attacker-useful shortcuts: the role name behind an instance's IAM
    # profile is the value you actually feed into ``aws iam`` calls;
    # ``principal_type`` is what classifies caller_identity rows.
    "iam_role",
    "principal_type",
)
# Fields that are always in the JSON report but add little in a terminal table.
_NOISY_FIELDS: frozenset[str] = frozenset(
    {"created", "last_used", "finished_at", "started_at", "max_session_duration"}
)
# Prefixes that mean the field belongs in a detail block, not the main table.
_NOISY_PREFIXES: tuple[str, ...] = ("scan_",)
# Exact field names that should never show up in the auto-picked table
# columns because they're handled by a dedicated detail renderer.
_DETAIL_ONLY_FIELDS: frozenset[str] = frozenset(
    {
        "policy_document",
        "inline_policies",
        "attached_policies",
        "assume_role_policy",
        "env_vars",
        "app_settings",
        "connection_strings",
        "firewall_rules",
        "role_bindings",
        "definition",
        "definition_language",
        "script",
        "startup_script",
        "user_data",
        "script_language",
        "secrets_found",
        "identity_details",
        "code_files",
        "handler_excerpt",
        "access_keys",
        "shared_with",
        "event_sources",
        "extensions",
    }
)
_MAX_EXTRA_COLUMNS = 4


def render_identity(console: Console, identity: Mapping[str, Any]) -> None:
    """Render a compact panel describing the authenticated principal."""
    rows: list[tuple[str, str]] = []
    for label, key in (
        ("Provider", "provider"),
        ("Principal", "principal"),
        ("Display name", "display_name"),
        ("Tenant / account", "tenant_or_account"),
        ("Auth method", "auth_method"),
    ):
        value = identity.get(key)
        if value:
            rows.append((label, str(value)))
    console.print(Panel(_kv_table(rows), title="authentication", border_style="info"))


def render_config(
    console: Console,
    provider: Provider,
    scope: Scope,
    *,
    extras: Mapping[str, Any] | None = None,
) -> None:
    """Render the planned enumeration scope as a panel."""
    rows: list[tuple[str, str]] = [("Provider", provider.value)]
    if scope.regions:
        rows.append(("Regions", _join(scope.regions)))
    if scope.subscription_ids:
        rows.append(("Subscriptions", _join(scope.subscription_ids)))
    if scope.project_ids:
        rows.append(("Projects", _join(scope.project_ids)))
    if scope.services:
        rows.append(("Services", _join(scope.services)))
    else:
        rows.append(("Services", "(all registered)"))
    rows.append(("Max concurrency", str(scope.max_concurrency)))
    rows.append(("Timeout (s)", str(scope.timeout_s)))
    if scope.deep_scan:
        rows.append(("Deep scan", "yes"))
    if scope.secret_scan:
        rows.append(("Secret scan", "yes"))
    if scope.iam_policy_bodies:
        rows.append(("IAM policy bodies", "yes"))
    if scope.s3_secret_scan:
        rows.append(
            (
                "S3 object scan",
                f"yes (limits: {scope.s3_scan_file_limit} files / {scope.s3_scan_size_limit_kb} KB)",
            )
        )
    for label, value in (extras or {}).items():
        rows.append((label, str(value)))
    console.print(Panel(_kv_table(rows), title="enumeration", border_style="info"))


_AUTH_ERROR_HINTS: tuple[str, ...] = (
    # Azure / Graph
    "AuthorizationFailed",
    "Authorization_RequestDenied",
    # GCP
    "permission_denied",
    "IAM_PERMISSION_DENIED",
    # AWS — error codes. ``AuthorizationError``/``AuthorizationErrorException``
    # are what SNS raises; ``UnauthorizedOperation`` is EC2/VPC; ``AccessDenied``
    # is the universal STS/IAM shape.
    "AccessDenied",
    "AuthorizationError",
    "UnauthorizedOperation",
    "PermissionDenied",
    # Message substrings that appear across providers regardless of code
    "not authorized to perform",
    "is not authorized",
    "insufficient privileges",
    "required scopes are missing",
    "does not have authorization",
    "does not have permission",
    "you don't have permission",
    "403 ",
    "Forbidden",
    # Optional-SDK fallthrough — keeps the "module not installed" line out of
    # the terminal but still in the JSON report.
    "not installed",
)


def _is_auth_error(message: str) -> bool:
    m = message.lower()
    return any(h.lower() in m for h in _AUTH_ERROR_HINTS)


def render_service(console: Console, result: ServiceResult) -> None:
    """Render one service's resources and errors.

    Silently drops services that returned no resources and whose only
    errors are authorization/permission / optional-SDK-missing failures —
    the full details remain in the JSON report and the summary table still
    shows the error count, but the terminal stays uncluttered.
    """
    if not result.resources and not result.errors:
        return
    if not result.resources and all(_is_auth_error(str(e)) for e in result.errors):
        return

    console.print()
    console.print(f"[info]{result.provider.value}[/info] / [bold]{result.service}[/bold]")

    for kind, rows in _group_by_kind(result.resources).items():
        _render_kind_block(console, kind, rows)

    visible_errors = [e for e in result.errors if not _is_auth_error(str(e))]
    suppressed = len(result.errors) - len(visible_errors)
    for err in visible_errors:
        console.print(f"  [error]error:[/error] {_escape_markup(str(err))}")
    if suppressed:
        console.print(
            f"  [muted]({suppressed} permission-denied error{'s' if suppressed != 1 else ''} "
            f"hidden — see report)[/muted]"
        )


def render_summary(console: Console, run: EnumerationRun) -> None:
    """Render the per-service breakdown plus run-level totals."""
    table = Table(box=SIMPLE_HEAVY, show_lines=False, expand=False, pad_edge=False)
    table.add_column("service", style="bold")
    table.add_column("resources", justify="right")
    table.add_column("errors", justify="right")
    table.add_column("duration_s", justify="right")
    rows = sorted(run.services, key=lambda s: (-s.count, s.service))
    for svc in rows:
        err_count = len(svc.errors)
        err_text = f"[error]{err_count}[/error]" if err_count else "[muted]0[/muted]"
        res_text = str(svc.count) if svc.count else "[muted]0[/muted]"
        table.add_row(svc.service, res_text, err_text, f"{svc.duration_s:.2f}")

    totals = (
        f"[success]{run.resource_total()}[/success] resources  "
        f"across [info]{len(run.services)}[/info] services  "
        f"in [info]{run.duration_s:.2f}s[/info]  "
        f"({run.error_total()} non-fatal errors)"
    )
    console.print()
    console.print(Panel(table, title=f"summary: {run.provider.value}", border_style="success"))
    console.print(totals)


def _render_kind_block(console: Console, kind: str, rows: list[dict[str, Any]]) -> None:
    console.print(f"  [muted]{kind}[/muted] ([info]{len(rows)}[/info])")
    columns = _pick_columns(rows)
    table = Table(box=SIMPLE_HEAVY, show_lines=False, expand=False, pad_edge=False)
    for col in columns:
        table.add_column(col, overflow="fold", no_wrap=False)
    for row in rows:
        table.add_row(*[_cell(row.get(col)) for col in columns])
    console.print(table)

    for row in rows:
        _render_row_details(console, row)


def _render_row_details(console: Console, row: dict[str, Any]) -> None:
    """Render opt-in deep-scan detail blocks.

    Each renderer is keyed off a well-known field on the resource dict
    so services never need to call display helpers directly — they just
    attach ``policy_document`` / ``env_vars`` / ``definition`` / etc.
    and this function picks them up.
    """
    label = str(row.get("name") or row.get("id") or row.get("arn") or "")

    policy_doc = row.get("policy_document")
    if isinstance(policy_doc, (dict, list)):
        _render_policy_document(console, label or "policy", policy_doc)

    assume_doc = row.get("assume_role_policy")
    if isinstance(assume_doc, (dict, list)):
        _render_policy_document(console, f"trust: {label}", assume_doc)

    inline = row.get("inline_policies")
    if isinstance(inline, list) and inline:
        _render_inline_policies(console, label, inline)

    attached = row.get("attached_policies")
    if isinstance(attached, list) and attached:
        _render_attached_policies(console, label, attached)

    code_files = row.get("code_files")
    if isinstance(code_files, list) and code_files:
        _render_code_files(console, label, code_files)

    handler_excerpt = row.get("handler_excerpt")
    if isinstance(handler_excerpt, str) and handler_excerpt.strip():
        runtime = str(row.get("runtime") or "")
        _render_code_panel(
            console, f"handler: {label}", handler_excerpt, _language_for_runtime(runtime)
        )

    if isinstance(row.get("env_vars"), Mapping) and row["env_vars"]:
        _render_kv_panel(console, f"env: {label}", row["env_vars"], mask_values=True)

    if isinstance(row.get("app_settings"), Mapping) and row["app_settings"]:
        _render_kv_panel(console, f"settings: {label}", row["app_settings"], mask_values=True)

    if isinstance(row.get("connection_strings"), Mapping) and row["connection_strings"]:
        _render_kv_panel(
            console, f"connections: {label}", row["connection_strings"], mask_values=True
        )

    if isinstance(row.get("firewall_rules"), list) and row["firewall_rules"]:
        _render_rule_table(console, f"firewall: {label}", row["firewall_rules"])

    if isinstance(row.get("role_bindings"), list) and row["role_bindings"]:
        _render_role_bindings(console, f"iam: {label}", row["role_bindings"])

    definition = row.get("definition")
    if isinstance(definition, (str, dict, list)) and definition:
        lang = str(row.get("definition_language") or _guess_language(definition))
        _render_code_panel(console, f"definition: {label}", definition, lang)

    script = row.get("script") or row.get("startup_script") or row.get("user_data")
    if isinstance(script, str) and script.strip():
        title_kind = "script" if "script" in row else "user-data"
        lang = str(row.get("script_language") or "bash")
        _render_code_panel(console, f"{title_kind}: {label}", script, lang)

    identity_details = row.get("identity_details")
    if isinstance(identity_details, Mapping) and identity_details:
        _render_identity_panel(console, label, identity_details)

    if "scan_files_found" in row:
        _render_scan_stats(console, label, row)

    secrets = row.get("secrets_found")
    if isinstance(secrets, list) and secrets:
        _render_secret_findings(console, label, secrets)


def _render_scan_stats(console: Console, bucket: str, row: Mapping[str, Any]) -> None:
    rows = [
        ("Files found", str(row.get("scan_files_found", 0))),
        ("Files scanned", str(row.get("scan_files_scanned", 0))),
        ("Skipped (size)", str(row.get("scan_files_skipped_size", 0))),
        ("Skipped (type)", str(row.get("scan_files_skipped_type", 0))),
        ("Secrets found", str(len(row.get("secrets_found") or []))),
    ]
    console.print(
        Panel(
            _kv_table(rows),
            title=f"scan: {bucket}",
            border_style="muted",
            padding=(0, 1),
        )
    )


def _render_policy_document(
    console: Console, name: str, doc: Mapping[str, Any] | list[Any]
) -> None:
    rendered = json.dumps(doc, indent=2, default=str)
    console.print(
        Panel(
            Syntax(rendered, "json", theme="ansi_dark", word_wrap=True, background_color="default"),
            title=f"policy: {name}",
            border_style="muted",
            padding=(0, 1),
        )
    )


def _render_inline_policies(
    console: Console, owner: str, policies: list[Mapping[str, Any]]
) -> None:
    """Render each inline-policy body as its own syntax-highlighted panel.

    Inline policies are where training labs (and most real environments)
    hide the high-value permissions — ``iam:PassRole``,
    ``bedrock:InvokeModel``, ``ecr:PutImage``. Rendering each body
    verbatim means the operator doesn't need to chase them with
    ``aws iam get-role-policy``.
    """
    for entry in policies:
        name = str(entry.get("name") or "inline")
        body = entry.get("policy_document")
        if isinstance(body, (dict, list)):
            _render_policy_document(console, f"{owner} / inline: {name}", body)
        elif body:
            _render_code_panel(console, f"{owner} / inline: {name}", body, "text")


def _render_attached_policies(
    console: Console, owner: str, policies: list[Mapping[str, Any]]
) -> None:
    """Render the list of attached managed policies as a compact table."""
    rows: list[tuple[str, str]] = []
    for entry in policies:
        rows.append((str(entry.get("name") or ""), str(entry.get("arn") or "")))
    if not rows:
        return
    console.print(
        Panel(
            _kv_table(rows),
            title=f"{owner} / attached policies ({len(rows)})",
            border_style="muted",
            padding=(0, 1),
        )
    )


def _render_code_files(
    console: Console, owner: str, code_files: list[Mapping[str, Any]]
) -> None:
    """Render a one-line-per-file table for Lambda deployment packages."""
    table = Table(box=SIMPLE_HEAVY, show_lines=False, expand=False, pad_edge=False)
    for col in ("path", "size", "note"):
        table.add_column(col, overflow="fold")
    for entry in code_files:
        note_parts: list[str] = []
        if entry.get("is_handler"):
            note_parts.append("[info]handler[/info]")
        if entry.get("secrets_found"):
            note_parts.append(
                f"[error]{len(entry['secrets_found'])} secret(s)[/error]"
            )
        if entry.get("note"):
            note_parts.append(str(entry["note"]))
        table.add_row(
            str(entry.get("path", "")),
            str(entry.get("size", "")),
            " ".join(note_parts),
        )
    console.print(
        Panel(
            table,
            title=f"{owner} / code ({len(code_files)} files)",
            border_style="muted",
            padding=(0, 1),
        )
    )


_RUNTIME_LANGUAGE: dict[str, str] = {
    "python": "python",
    "nodejs": "javascript",
    "node": "javascript",
    "ruby": "ruby",
    "go": "go",
    "java": "java",
    "dotnet": "csharp",
    "provided": "bash",
}


def _language_for_runtime(runtime: str) -> str:
    """Best-effort language pick for a Lambda ``runtime`` identifier."""
    lowered = runtime.lower()
    for prefix, lang in _RUNTIME_LANGUAGE.items():
        if lowered.startswith(prefix):
            return lang
    return "text"


def _render_code_panel(
    console: Console, title: str, body: Any, language: str
) -> None:
    """Render ``body`` as a syntax-highlighted panel.

    ``body`` may be a string (used as-is) or a JSON-serialisable
    object; dicts/lists are pretty-printed with ``json`` highlighting
    irrespective of ``language``.
    """
    if isinstance(body, (dict, list)):
        text = json.dumps(body, indent=2, default=str)
        lang = "json"
    else:
        text = str(body)
        lang = language or "text"
    console.print(
        Panel(
            Syntax(text, lang, theme="ansi_dark", word_wrap=True, background_color="default"),
            title=title,
            border_style="muted",
            padding=(0, 1),
        )
    )


def _render_kv_panel(
    console: Console,
    title: str,
    mapping: Mapping[str, Any],
    *,
    mask_values: bool = False,
) -> None:
    """Render a ``name -> value`` map inside a muted panel.

    When ``mask_values`` is true, values whose key or content looks
    sensitive are partially redacted; non-sensitive values are shown
    verbatim so the user can still read plain URLs or region strings.
    """
    from cloud_service_enum.core.secrets import SENSITIVE_NAME_HINTS, mask

    rows: list[tuple[str, str]] = []
    for key, value in sorted(mapping.items()):
        text = "" if value is None else str(value)
        if mask_values:
            lowered = str(key).lower()
            if any(hint in lowered for hint in SENSITIVE_NAME_HINTS) and len(text) >= 8:
                text = mask(text)
        rows.append((str(key), text))
    if not rows:
        return
    console.print(
        Panel(_kv_table(rows), title=title, border_style="muted", padding=(0, 1))
    )


def _render_rule_table(
    console: Console, title: str, rules: list[dict[str, Any]]
) -> None:
    """Render a list of rule dicts (firewall / auth / WAF) as a table."""
    if not rules:
        return
    # Collect columns from the first rule plus any extras on later rules.
    cols: list[str] = []
    for r in rules:
        for k in r:
            if k not in cols:
                cols.append(k)
    table = Table(box=SIMPLE_HEAVY, show_lines=False, expand=False, pad_edge=False)
    for c in cols:
        table.add_column(c, overflow="fold")
    for r in rules:
        table.add_row(*[_cell(r.get(c)) for c in cols])
    console.print(
        Panel(table, title=title, border_style="muted", padding=(0, 1))
    )


_DANGEROUS_ROLE_HINTS: tuple[str, ...] = (
    "tokenCreator",
    "serviceAccountUser",
    "workloadIdentityUser",
    "serviceAccountKeyAdmin",
    "serviceAccountAdmin",
    "actAs",
    "roles/owner",
    "roles/editor",
)


def _render_role_bindings(
    console: Console, title: str, bindings: list[dict[str, Any]]
) -> None:
    """Render IAM role bindings (principal / role / condition) in a table.

    Accepts either the Azure shape (``{principal, role, condition}``, one
    member per binding) or the GCP shape (``{role, members: [...]}``, which
    is expanded into one row per member). Dangerous impersonation roles
    (``tokenCreator``, ``serviceAccountUser`` etc.) are highlighted so they
    stand out to security auditors.
    """
    table = Table(box=SIMPLE_HEAVY, show_lines=False, expand=False, pad_edge=False)
    for col in ("principal", "role", "condition"):
        table.add_column(col, overflow="fold")
    for b in bindings:
        role = b.get("role") or b.get("role_name") or b.get("role_definition_id") or ""
        condition = b.get("condition") or b.get("conditions") or ""
        if isinstance(condition, (dict, list)):
            condition = json.dumps(condition, default=str)
        members: list[str] = []
        if isinstance(b.get("members"), list) and b["members"]:
            members = [str(m) for m in b["members"]]
        else:
            principal = b.get("principal") or b.get("member") or b.get("principal_id")
            members = [str(principal or "")]
        styled_role = (
            f"[error]{role}[/error]"
            if any(h in role for h in _DANGEROUS_ROLE_HINTS)
            else str(role)
        )
        for m in members:
            table.add_row(m, styled_role, str(condition))
    console.print(
        Panel(table, title=title, border_style="muted", padding=(0, 1))
    )


def _guess_language(body: Any) -> str:
    """Pick a syntax-highlighting language for a definition body."""
    if isinstance(body, (dict, list)):
        return "json"
    if isinstance(body, str):
        stripped = body.lstrip()
        if stripped.startswith("{") or stripped.startswith("["):
            return "json"
        if stripped.startswith("<"):
            return "xml"
        if stripped.startswith("#!/") or stripped.startswith("#!"):
            first = stripped.splitlines()[0].lower()
            if "python" in first:
                return "python"
            if "powershell" in first or "pwsh" in first:
                return "powershell"
            return "bash"
    return "text"


def _render_identity_panel(
    console: Console, label: str, details: Mapping[str, Any]
) -> None:
    """Render managed-identity details (system principal + UAMI resource ids).

    Mirrors how AWS role trust relationships and Azure role assignments are
    displayed: one compact table so an auditor can correlate the identity
    with role bindings on downstream resources.
    """
    rows: list[tuple[str, str]] = []
    system = details.get("system_principal_id")
    if system:
        rows.append(("system principal", str(system)))
    user_assigned = details.get("user_assigned") or []
    for i, uami in enumerate(user_assigned):
        rows.append((f"user-assigned[{i}]", str(uami)))
    if not rows:
        return
    console.print(
        Panel(
            _kv_table(rows),
            title=f"identity: {label}",
            border_style="muted",
            padding=(0, 1),
        )
    )


def _render_secret_findings(console: Console, bucket: str, findings: list[dict[str, Any]]) -> None:
    """Render findings with a confidence column so hints don't cry wolf.

    Low-confidence hits (placeholder AKIA strings, ``DEPLOY_*`` env-var
    names) are styled in muted grey with a ``(hint)`` suffix so the eye
    skips over them unless nothing else is there.
    """
    table = Table(box=SIMPLE_HEAVY, show_lines=False, expand=False, pad_edge=False)
    for col in ("file", "type", "line", "value", "confidence"):
        table.add_column(col, overflow="fold")
    high_count = 0
    for f in findings:
        confidence = str(f.get("confidence", "high"))
        is_low = confidence == "low"
        if not is_low:
            high_count += 1
        row_type = str(f.get("type", ""))
        conf_cell = (
            "[muted]low (hint)[/muted]" if is_low else "[error]high[/error]"
        )
        value_cell = str(f.get("value", ""))
        if is_low:
            row_type = f"[muted]{row_type}[/muted]"
            value_cell = f"[muted]{value_cell}[/muted]"
        table.add_row(
            str(f.get("file", "")),
            row_type,
            str(f.get("line", "")),
            value_cell,
            conf_cell,
        )
    border = "error" if high_count else "warning"
    title_style = "error" if high_count else "warning"
    console.print(
        Panel(
            table,
            title=f"[{title_style}]secrets in {bucket}[/{title_style}] ({len(findings)})",
            border_style=border,
            padding=(0, 1),
        )
    )


def _group_by_kind(resources: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Preserve insertion order while bucketing rows by ``kind``."""
    groups: dict[str, list[dict[str, Any]]] = {}
    for r in resources:
        key = str(r.get("kind") or "resource")
        groups.setdefault(key, []).append(r)
    return groups


def _kv_table(rows: Iterable[tuple[str, str]]) -> Table:
    table = Table.grid(padding=(0, 2))
    table.add_column(style="muted", no_wrap=True)
    table.add_column()
    for label, value in rows:
        table.add_row(label, value)
    return table


def _join(values: Iterable[str], limit: int = 6) -> str:
    items = list(values)
    if len(items) <= limit:
        return ", ".join(items)
    return ", ".join(items[:limit]) + f", … (+{len(items) - limit} more)"


def _pick_columns(resources: list[dict[str, Any]]) -> list[str]:
    """Choose preferred columns plus a few short scalar extras.

    Rules:
      - Always include preferred fields (kind/id/arn/name/region) that appear.
      - Skip dict/list values — they wrap terribly in a terminal; they go in
        the JSON report and in per-row detail panels instead.
      - Skip known-noisy timestamp fields (`created`, `last_used`, etc.).
      - Cap extras at :data:`_MAX_EXTRA_COLUMNS`.
    """
    cols: list[str] = []
    seen: set[str] = set()
    for col in _PREFERRED_COLUMNS:
        if any(col in row for row in resources):
            cols.append(col)
            seen.add(col)
    extras: list[str] = []
    for row in resources:
        for key, value in row.items():
            if key in seen or key in extras or key in _NOISY_FIELDS:
                continue
            if key in _DETAIL_ONLY_FIELDS:
                continue
            if key.startswith(_NOISY_PREFIXES):
                continue
            if isinstance(value, (dict, list, datetime, date)):
                continue
            extras.append(key)
            if len(extras) >= _MAX_EXTRA_COLUMNS:
                break
        if len(extras) >= _MAX_EXTRA_COLUMNS:
            break
    return cols + extras


def _cell(value: Any) -> str:
    if value is None:
        return "[muted]-[/muted]"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return str(value)
