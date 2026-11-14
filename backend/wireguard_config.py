"""WARP-safe AmneziaWG/WireGuard tunnel configuration builder.

Shared obfuscation params stay at the community-proven WARP-safe identity set
(S1..S4 = 0, H1..H4 = 1..4) so the config works against Cloudflare's stock
WireGuard edge; client-side-only junk packets (Jc/Jmin/Jmax) are the DPI
resistance knob. References: run evidence/research-amneziawg.md.
"""

from __future__ import annotations

PEER_PUBLIC_KEY = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
DEFAULT_ENDPOINT = "engage.cloudflareclient.com:2408"
DEFAULT_MTU = 1280
DEFAULT_KEEPALIVE = 25
DEFAULT_DNS = "1.1.1.1"

# Shared params must match the peer; identity values disable obfuscation.
IDENTITY_PARAMS = {
    "S1": 0,
    "S2": 0,
    "S3": 0,
    "S4": 0,
    "H1": 1,
    "H2": 2,
    "H3": 3,
    "H4": 4,
}

# Client-side-only junk packets (receiver drops them as unknown UDP).
DEFAULT_JUNK = {"Jc": 4, "Jmin": 40, "Jmax": 70}


def validate_junk_params(jc: int, jmin: int, jmax: int) -> None:
    """Enforce the AmneziaWG client-side junk-packet constraints."""
    if not 1 <= int(jc) <= 128:
        raise ValueError("Jc must be between 1 and 128")
    if not 0 <= int(jmin) < int(jmax) <= 1280:
        raise ValueError("Jmin/Jmax must satisfy 0 <= Jmin < Jmax <= 1280")


def validate_shared_params(params: dict[str, int]) -> None:
    """Enforce AWG shared-parameter sanity for the identity/zero set."""
    if params["S1"] + 56 == params["S2"]:
        # Init and response packets would collide to identical sizes.
        raise ValueError("S1 + 56 must not equal S2")


def build_tunnel_config(
    private_key_b64: str,
    address_v4: str,
    address_v6: str = "",
    endpoint: str = DEFAULT_ENDPOINT,
    junk: dict[str, int] | None = None,
    include_junk: bool = True,
    mtu: int = DEFAULT_MTU,
    keepalive: int = DEFAULT_KEEPALIVE,
    dns: str = DEFAULT_DNS,
    profile: str = "amneziawg",
) -> str:
    """Build the [Interface]/[Peer] config.

    profile="amneziawg" adds the WARP-safe obfuscation keys (identity shared
    params + client-side junk); profile="wireguard" emits a plain WARP config
    because the stock WireGuard parser rejects unknown [Interface] keys.
    """
    lines = ["[Interface]", f"PrivateKey = {private_key_b64}"]
    addresses = ", ".join(a for a in (address_v4, address_v6) if a)
    if addresses:
        lines.append(f"Address = {addresses}")
    if dns:
        lines.append(f"DNS = {dns}")
    lines.append(f"MTU = {mtu}")
    if profile == "amneziawg":
        validate_shared_params(IDENTITY_PARAMS)
        if include_junk:
            params = dict(junk or DEFAULT_JUNK)
            validate_junk_params(params["Jc"], params["Jmin"], params["Jmax"])
            lines.append(f"Jc = {params['Jc']}")
            lines.append(f"Jmin = {params['Jmin']}")
            lines.append(f"Jmax = {params['Jmax']}")
        for key, value in IDENTITY_PARAMS.items():
            lines.append(f"{key} = {value}")
    lines.append("")
    lines.append("[Peer]")
    lines.append(f"PublicKey = {PEER_PUBLIC_KEY}")
    lines.append("AllowedIPs = 0.0.0.0/0, ::/0")
    lines.append(f"Endpoint = {endpoint}")
    lines.append(f"PersistentKeepalive = {keepalive}")
    return "\n".join(lines) + "\n"
