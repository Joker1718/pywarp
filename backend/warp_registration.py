"""Cloudflare WARP device registration for the native WireGuard path.

Registers a WARP device against the current api.cloudflareclient.com shape
and converts responses into tunnel-config inputs. The API gates non-Android
clients (path version, UA, CF-Client-Version, TLS fingerprint) — 429/403 map
to RegistrationBlocked so callers can fall back to config import.
Reference: run evidence/research-warp-registration-api.md.

shortcut: no uTLS fingerprint emulation in Python stdlib, registration may be
rejected with 429 on some networks — config import is the supported fallback;
revisit (curl_cffi-style dependency) if 429s become universal.
"""

from __future__ import annotations

import base64
import os
from typing import Any

import requests

API_BASE = "https://api.cloudflareclient.com"
API_VERSION = "v0a5641"
CLIENT_VERSION = "a-6.38.9-5641"
USER_AGENT = "1.1.1.1/6.38.9-5641 (Android 16.0.0)"

DEFAULT_ADDRESS_V4 = "172.16.0.2/32"
DEFAULT_ADDRESS_V6 = "2606:4700:110:89a3::1/128"
DEFAULT_ENDPOINT = "engage.cloudflareclient.com:2408"


class RegistrationError(Exception):
    """Registration failed for a retryable/unknown reason."""


class RegistrationBlocked(RegistrationError):
    """The API rejected a non-Android-looking client (429/403 gating)."""


class ConfigError(Exception):
    """An imported WireGuard config is invalid."""


# --- X25519 (RFC 7748), pure Python; one keygen per registration. ---

_P = 2**255 - 19
_A24 = 121665
_BASEPOINT = b"\x09" + b"\x00" * 31


def _clamp_scalar(scalar: bytes) -> int:
    value = bytearray(scalar)
    value[0] &= 248
    value[31] &= 127
    value[31] |= 64
    return int.from_bytes(value, "little")


def _x25519(scalar: bytes, u: bytes) -> bytes:
    k = _clamp_scalar(scalar)
    x1 = int.from_bytes(bytes(bytearray(u)[:31] + bytearray([u[31] & 127])), "little")
    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for t in reversed(range(255)):
        k_t = (k >> t) & 1
        swap ^= k_t
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = k_t
        a = (x2 + z2) % _P
        aa = a * a % _P
        b = (x2 - z2) % _P
        bb = b * b % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = d * a % _P
        cb = c * b % _P
        x3 = (da + cb) % _P
        x3 = x3 * x3 % _P
        z3 = (da - cb) % _P
        z3 = z3 * z3 % _P
        z3 = z3 * x1 % _P
        x2 = aa * bb % _P
        z2 = e * (aa + _A24 * e) % _P
    if swap:
        x2, x3, z2, z3 = x3, x2, z3, z2
    return ((x2 * pow(z2, _P - 2, _P)) % _P).to_bytes(32, "little")


def generate_private_key() -> bytes:
    return os.urandom(32)


def public_key(private: bytes, u: bytes = _BASEPOINT) -> bytes:
    return _x25519(private, u)


def public_key_b64(private: bytes) -> str:
    return base64.b64encode(public_key(private)).decode()


# --- Registration API ---


def registration_url() -> str:
    return f"{API_BASE}/{API_VERSION}/reg"


def registration_headers() -> dict[str, str]:
    return {
        "Content-Type": "application/json; charset=UTF-8",
        "User-Agent": USER_AGENT,
        "CF-Client-Version": CLIENT_VERSION,
        "Connection": "Keep-Alive",
    }


def build_registration_payload(public_key_b64_value: str, tos: str) -> dict[str, Any]:
    return {
        "key": public_key_b64_value,
        "install_id": "",
        "fcm_token": "",
        "key_type": "curve25519",
        "type": "Android",
        "model": "PC",
        "locale": "en_US",
        "tos": tos,
    }


def parse_registration_response(data: dict[str, Any]) -> dict[str, Any]:
    config = data.get("config") if isinstance(data.get("config"), dict) else {}
    account = data.get("account") if isinstance(data.get("account"), dict) else {}
    interface = config.get("interface") if isinstance(config.get("interface"), dict) else {}
    addresses = interface.get("addresses") if isinstance(interface.get("addresses"), dict) else {}
    peers = config.get("peers") if isinstance(config.get("peers"), list) else []
    endpoint = DEFAULT_ENDPOINT
    if peers and isinstance(peers[0], dict):
        peer_endpoint = peers[0].get("endpoint")
        if isinstance(peer_endpoint, dict):
            host = peer_endpoint.get("host") or peer_endpoint.get("v4") or peer_endpoint.get("v6")
            port = peer_endpoint.get("port")
            if host and port:
                endpoint = f"{host}:{port}"
    return {
        "device_id": str(data.get("id") or ""),
        "token": str(data.get("token") or ""),
        "license": str(account.get("license") or ""),
        "client_id": str(config.get("client_id") or ""),
        "address_v4": str(addresses.get("v4") or DEFAULT_ADDRESS_V4),
        "address_v6": str(addresses.get("v6") or DEFAULT_ADDRESS_V6),
        "endpoint": endpoint,
    }


def register_device(session: requests.Session, private: bytes, tos: str) -> dict[str, Any]:
    payload = build_registration_payload(public_key_b64(private), tos)
    try:
        response = session.post(
            registration_url(),
            json=payload,
            headers=registration_headers(),
            timeout=20,
        )
    except (requests.RequestException, OSError) as exc:
        raise RegistrationError(f"Registration request failed: {exc}") from exc
    if response.status_code in (429, 403):
        raise RegistrationBlocked(
            "Cloudflare rejected the registration (HTTP "
            f"{response.status_code}). The API gates non-Android clients; "
            "import an existing WARP WireGuard config instead."
        )
    if response.status_code >= 400:
        raise RegistrationError(
            f"Registration failed with HTTP {response.status_code}"
        )
    try:
        data = response.json()
    except ValueError as exc:
        raise RegistrationError("Registration returned invalid JSON") from exc
    return parse_registration_response(data)


def delete_device(session: requests.Session, token: str, device_id: str) -> None:
    try:
        response = session.delete(
            f"{registration_url()}/{device_id}",
            headers={"Authorization": f"Bearer {token}", **registration_headers()},
            timeout=20,
        )
    except requests.RequestException as exc:
        raise RegistrationError(f"Deletion request failed: {exc}") from exc
    # Upstream deactivate has returned 500 while still removing the device
    # (wgcf #515) — only auth failures are real errors here.
    if response.status_code in (401, 403):
        raise RegistrationError(
            f"Deletion failed with HTTP {response.status_code}"
        )


# --- Import fallback ---


def parse_wg_config(text: str) -> dict[str, Any]:
    """Parse a wg-quick/awg-quick style config (import fallback)."""
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")) or line.startswith("["):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip().lower()] = value.strip()
    private_key = values.get("privatekey")
    if not private_key:
        raise ConfigError("The config has no PrivateKey; it cannot be used.")
    v4, v6 = DEFAULT_ADDRESS_V4, ""
    for part in values.get("address", "").split(","):
        part = part.strip()
        if ":" in part:
            v6 = part
        elif part:
            v4 = part
    junk: dict[str, int] = {}
    for key in ("jc", "jmin", "jmax"):
        if key in values:
            junk["J" + key[1:]] = int(values[key])
    # Shared AWG params (S*/H*) are intentionally not carried over: the
    # import fallback targets WARP, whose configs are rebuilt with the
    # WARP-safe identity set (see wireguard_config.IDENTITY_PARAMS).
    mtu = int(values["mtu"]) if values.get("mtu", "").isdigit() else 1280
    return {
        "private_key": private_key,
        "address_v4": v4,
        "address_v6": v6,
        "endpoint": values.get("endpoint") or DEFAULT_ENDPOINT,
        "mtu": mtu,
        "junk": junk,
    }
