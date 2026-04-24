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
from typing import Any, Literal

Confidence = Literal["high", "low"]

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
    # Low-confidence environment-variable names commonly used to carry
    # AWS credentials in CI/CD pipelines and user-data bootstraps. Keeps
    # the "placeholder creds in user-data" training-lab case from being
    # silently dropped while leaving real-secret coverage untouched.
    "deploy_access_key",
    "deploy_secret_key",
    "deploy_access_secret",
)

# High-confidence patterns — strict shapes we trust enough to flag
# without further corroboration. These fire first.
_PATTERNS: tuple[tuple[str, re.Pattern[str], Confidence], ...] = (
    ("AWS Access Key", re.compile(r"\b(?:AKIA|ASIA|AIDA|ANPA|ANVA|AGPA|AROA|AIPA|ABIA)[0-9A-Z]{16}\b"), "high"),
    ("AWS Secret Key", re.compile(r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key['\"\s:=]+([A-Za-z0-9/+=]{40})"), "high"),
    ("GitHub Token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"), "high"),
    ("Private Key", re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY-----"), "high"),
    ("Slack Token", re.compile(r"\bxox[aboprs]-[A-Za-z0-9-]{10,}\b"), "high"),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "high"),
    ("Stripe Key", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{24,}\b"), "high"),
    ("Azure Storage Key", re.compile(r"\b[A-Za-z0-9+/]{86}==\b"), "high"),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), "high"),
    ("Generic API Key", re.compile(r"(?i)\b(?:api[_\-]?key|secret|token)['\"\s:=]+([A-Za-z0-9_\-]{32,})"), "high"),
    # Low-confidence placeholder catcher — matches ``AKIA`` followed by
    # underscores/digits/letters that doesn't satisfy the strict 16-char
    # shape above. Lets walkthroughs flag hard-coded placeholder keys
    # (e.g. ``AKIA_PLACEHOLDER_NORTHBRIDGE``) without drowning real
    # findings in noise.
    ("AWS Access Key (placeholder)", re.compile(r"\bAKIA[A-Z0-9_]{6,}\b"), "low"),
)


@dataclass
class SecretFinding:
    """A single regex hit inside a named text surface."""

    file: str
    line: int
    type: str
    value: str
    confidence: Confidence = "high"

    def as_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "type": self.type,
            "value": self.value,
            "confidence": self.confidence,
        }


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

    Low-confidence patterns (e.g. placeholder AKIA strings) only fire
    when no high-confidence pattern matched the same line, so real
    findings aren't shadowed by hints.
    """
    findings: list[SecretFinding] = []
    for lineno, line in enumerate(content.splitlines() or [content], start=1):
        high_hits: list[SecretFinding] = []
        low_hits: list[SecretFinding] = []
        for label, pattern, confidence in _PATTERNS:
            for match in pattern.finditer(line):
                value = match.group(1) if match.groups() else match.group(0)
                hit = SecretFinding(
                    file=file,
                    line=lineno,
                    type=label,
                    value=mask(value),
                    confidence=confidence,
                )
                (high_hits if confidence == "high" else low_hits).append(hit)
        findings.extend(high_hits)
        if not high_hits:
            findings.extend(low_hits)
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
            # Name-only matches are hints — they fire on benign values
            # with suspicious names, so we tag them as low-confidence
            # rather than crying wolf alongside real key material.
            findings.append(
                SecretFinding(
                    file=f"{source}[{key}]",
                    line=1,
                    type="Sensitive Name",
                    value=mask(str_value),
                    confidence="low",
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
