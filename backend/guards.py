"""Pure protocol/mode combination guards.

Cloudflare clients refuse some tunnel combinations outright (proxy mode is
MASQUE-only since client 2025.7.106.1); surfacing them here keeps the
refusal testable without Qt. Reference: run
evidence/research-warp-cli-surface.md (changelog 2025-09-10).
"""

from __future__ import annotations

PROXY_WIREGUARD_MESSAGE = (
    "Proxy mode needs MASQUE: Cloudflare clients only support MASQUE in "
    "Proxy mode (WireGuard would connect but route nothing)."
)

PROXY_MASQUE_H2_MESSAGE = (
    "Proxy mode cannot use MASQUE HTTP/2 only: HTTP/2 transport does not "
    "support the SOCKS5 proxy path."
)


def check_protocol_mode_guard(
    mode: str,
    protocol: str,
    masque_option: str = "auto",
) -> str | None:
    """Return a user-facing refusal message, or None when allowed."""
    if mode == "proxy":
        if protocol == "WireGuard":
            return PROXY_WIREGUARD_MESSAGE
        if protocol == "MASQUE" and masque_option == "h2-only":
            return PROXY_MASQUE_H2_MESSAGE
    return None
