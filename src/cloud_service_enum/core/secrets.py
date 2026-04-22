"""Regex-based secret scanner shared by every provider.

Detects the high-signal credential formats an attacker would act on:
AWS access keys, GitHub/Slack tokens, private keys, Google/Stripe/generic
API keys. Callers choose their own substrate: bucket objects (S3/GCS),
environment-variable maps (Lambda/App Service/Cloud Run), definition
bodies (Logic Apps/Step Functions/runbooks), or plain text files.

Precision is preferred over recall — findings are rendered to the
terminal and false positives drown out the real ones.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

TEXT_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".cfg",
        ".conf",
        ".csv",
        ".env",
        ".ini",
        ".json",
        ".log",
        ".md",
        ".properties",
        ".py",
        ".ps1",
        ".rb",
        ".rs",
        ".sh",
        ".sql",
        ".tf",
        ".toml",
        ".tsv",
        ".txt",
        ".xml",
        ".yaml",
        ".yml",
    }
)

# Labels matching names (case-insensitive substring) that flag an env-var
# / app-setting entry as sensitive even when the value itself looks plain.
SENSITIVE_NAME_HINTS: tuple[str, ...] = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "client_secret",
    "connection_string",
)

_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS Access Key", re.compile(r"\b(?:AKIA|ASIA|AIDA|ANPA|ANVA|AGPA|AROA|AIPA|ABIA)[0-9A-Z]{16}\b")),
    ("AWS Secret Key", re.compile(r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key['\"\s:=]+([A-Za-z0-9/+=]{40})")),
    ("GitHub Token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    ("Private Key", re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY-----")),
    ("Slack Token", re.compile(r"\bxox[aboprs]-[A-Za-z0-9-]{10,}\b")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Stripe Key", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{24,}\b")),
    ("Azure Storage Key", re.compile(r"\b[A-Za-z0-9+/]{86}==\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("Generic API Key", re.compile(r"(?i)\b(?:api[_\-]?key|secret|token)['\"\s:=]+([A-Za-z0-9_\-]{32,})")),
)


@dataclass
class SecretFinding:
    """A single regex hit inside a named text surface."""

    file: str
    line: int
    type: str
    value: str

    def as_dict(self) -> dict[str, Any]:
        return {"file": self.file, "line": self.line, "type": self.type, "value": self.value}


@dataclass
class ScanSummary:
    """Bucket-level counts returned by :func:`scan_bucket_for_secrets`."""

    files_found: int = 0
    files_scanned: int = 0
    files_skipped_size: int = 0
    files_skipped_type: int = 0
    findings: list[SecretFinding] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.findings is None:
            self.findings = []

    def as_dict(self) -> dict[str, Any]:
        return {
            "files_found": self.files_found,
            "files_scanned": self.files_scanned,
            "files_skipped_size": self.files_skipped_size,
            "files_skipped_type": self.files_skipped_type,
            "secrets_found": len(self.findings),
        }


def scan_text(file: str, content: str) -> list[SecretFinding]:
    """Regex-match every known credential pattern against ``content``.

    ``file`` is a free-form label included on every finding so the
    caller can locate the source (an S3 key, an env-var name, a runbook
    path, etc.).
    """
    findings: list[SecretFinding] = []
    for lineno, line in enumerate(content.splitlines() or [content], start=1):
        for label, pattern in _PATTERNS:
            for match in pattern.finditer(line):
                value = match.group(1) if match.groups() else match.group(0)
                findings.append(
                    SecretFinding(file=file, line=lineno, type=label, value=mask(value))
                )
    return findings


def scan_mapping(
    source: str, env: Mapping[str, str] | Mapping[str, Any] | None
) -> list[SecretFinding]:
    """Scan a ``name -> value`` mapping (env vars, app settings, connection strings).

    Flags entries whose value matches a known credential pattern *or*
    whose name contains a sensitive hint (``password``/``secret``/
    ``api_key`` etc.) and whose value is non-trivial (>=8 chars).

    ``source`` is included on every finding so the caller can link the
    hit back to the owning resource (e.g. the Lambda ARN or App Service
    name).
    """
    if not env:
        return []
    findings: list[SecretFinding] = []
    for key, value in env.items():
        if value is None:
            continue
        str_value = str(value)
        if not str_value:
            continue
        hits = scan_text(f"{source}[{key}]", str_value)
        if hits:
            findings.extend(hits)
            continue
        lowered = key.lower()
        if any(hint in lowered for hint in SENSITIVE_NAME_HINTS) and len(str_value) >= 8:
            findings.append(
                SecretFinding(
                    file=f"{source}[{key}]",
                    line=1,
                    type="Sensitive Name",
                    value=mask(str_value),
                )
            )
    return findings


def mask(value: str) -> str:
    """Show the first 8 characters then mask the rest so secrets aren't fully echoed."""
    if len(value) <= 12:
        return value
    return f"{value[:8]}…{value[-4:]}"


def ext(key: str) -> str:
    dot = key.rfind(".")
    return key[dot:].lower() if dot >= 0 else ""
