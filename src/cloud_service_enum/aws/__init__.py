"""Async AWS enumerator package.

Importing this package registers every service with the shared
:data:`cloud_service_enum.core.registry`.
"""

from __future__ import annotations

from cloud_service_enum.aws.auth import AwsAuthenticator

from cloud_service_enum.aws import services as _services  # noqa: F401 - side-effect

__all__ = ["AwsAuthenticator"]
