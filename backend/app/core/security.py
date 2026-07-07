"""Local-first security helpers: origin guard and scan-target authorization."""

from __future__ import annotations

import ipaddress

from fastapi import Request

from backend.app.config import settings


def origin_allowed(request: Request) -> bool:
    """Allow same-origin/no-origin (curl, native app) and configured origins only."""
    origin = request.headers.get("origin")
    if origin is None:
        return True  # non-browser client (CLI, tests, WebSocket handshake tools)
    return origin in settings.allowed_origins


class TargetValidationError(ValueError):
    """Raised when a scan target is malformed or not authorized."""


def validate_target(target: str, authorized: bool, allow_public: bool | None = None) -> str:
    """Validate and normalize a scan target.

    Enforces the authorization gate and (by default) blocks public IP ranges so
    users cannot accidentally scan networks they do not own.
    """
    target = (target or "").strip()
    if not target:
        raise TargetValidationError("target is required")
    if not authorized:
        raise TargetValidationError(
            "authorization required: confirm you own or are permitted to scan this target"
        )

    allow_public = settings.allow_public_targets if allow_public is None else allow_public

    # Determine the address(es) implied by the target for the public-range check.
    nets: list[ipaddress._BaseNetwork] = []
    try:
        if "/" in target:
            nets = [ipaddress.ip_network(target, strict=False)]
        else:
            try:
                nets = [ipaddress.ip_network(f"{target}/32", strict=False)]
            except ValueError:
                nets = []  # hostname — resolved later by the engine
    except ValueError as exc:
        raise TargetValidationError(f"invalid target: {target}") from exc

    if not allow_public:
        for net in nets:
            if not (net.is_private or net.is_loopback or net.is_link_local):
                raise TargetValidationError(
                    "public IP ranges are blocked; enable allow_public_targets to override"
                )
    return target
