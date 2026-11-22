"""Hue Secure cloud API client (OAuth PKCE, devices, KVS signaling)."""
from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json
import logging
import os
import time
import urllib.parse
from typing import Any, Optional

import aiohttp
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import (
    AUDIENCE,
    AUTH_URL,
    CLIENT_ID,
    HUE_DEVICES_URL,
    HUE_LIVE_STREAM_URL,
    HUE_WAKE_URL,
    REDIRECT_URI,
    SCOPE,
    TOKEN_URL,
)

_LOGGER = logging.getLogger(__name__)


# ── PKCE ─────────────────────────────────────────────────────────────────────

def make_pkce() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge


def build_auth_url(verifier: str) -> str:
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    state = base64.urlsafe_b64encode(os.urandom(12)).decode().rstrip("=")
    params = urllib.parse.urlencode(
        {
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
            "scope": SCOPE,
            "audience": AUDIENCE,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state,
        }
    )
    return f"{AUTH_URL}?{params}"


def _jwt_exp(token: str) -> int:
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        return int(json.loads(base64.b64decode(part)).get("exp", 0))
    except Exception:
        return 0


async def async_exchange_code(hass: HomeAssistant, code: str, verifier: str) -> dict[str, Any]:
    session = async_get_clientsession(hass, verify_ssl=False)
    async with session.post(
        TOKEN_URL,
        data={
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
        },
    ) as resp:
        body = await resp.text()
        if resp.status != 200:
            raise RuntimeError(f"Token exchange failed: {resp.status} {body[:200]}")
        return json.loads(body)


async def async_refresh(hass: HomeAssistant, refresh_token: str) -> Optional[dict[str, Any]]:
    session = async_get_clientsession(hass, verify_ssl=False)
    try:
        async with session.post(
            TOKEN_URL,
            data={
                "grant_type": "refresh_token",
                "client_id": CLIENT_ID,
                "refresh_token": refresh_token,
                "audience": AUDIENCE,
            },
        ) as resp:
            if resp.status == 200:
                return await resp.json()
            _LOGGER.warning("Token refresh HTTP %d", resp.status)
    except aiohttp.ClientError as exc:
        _LOGGER.warning("Token refresh failed: %s", exc)
    return None


def token_needs_refresh(token: str) -> bool:
    exp = _jwt_exp(token)
    return bool(exp) and time.time() >= exp - 300


# ── Cloud API ────────────────────────────────────────────────────────────────

def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


async def async_get_devices(hass: HomeAssistant, token: str, home_id: str) -> list[dict[str, Any]]:
    session = async_get_clientsession(hass, verify_ssl=False)
    async with session.get(HUE_DEVICES_URL.format(home_id=home_id), headers=_auth(token)) as resp:
        if resp.status == 403:
            raise RuntimeError("Forbidden – Home-ID falsch?")
        resp.raise_for_status()
        data = await resp.json()
    cameras = []
    for item in data:
        reported = item.get("reported", item)
        service = reported.get("service", {})
        if "camera" in service:
            cameras.append(
                {
                    "id": reported.get("id", ""),
                    "name": reported.get("metadata", {}).get("name", reported.get("id", "")),
                }
            )
    return cameras


async def async_wake(hass: HomeAssistant, token: str, home_id: str, device_id: str) -> None:
    session = async_get_clientsession(hass, verify_ssl=False)
    async with session.put(
        HUE_WAKE_URL.format(home_id=home_id, device_id=device_id),
        headers=_auth(token),
        json={"action_type": "wake_up"},
    ) as resp:
        if resp.status not in (200, 202):
            _LOGGER.debug("wake_up HTTP %d", resp.status)


async def async_reboot(hass: HomeAssistant, token: str, home_id: str, device_id: str) -> None:
    session = async_get_clientsession(hass, verify_ssl=False)
    async with session.put(
        HUE_WAKE_URL.format(home_id=home_id, device_id=device_id),
        headers=_auth(token),
        json={"action_type": "reboot"},
    ) as resp:
        if resp.status not in (200, 202):
            _LOGGER.debug("reboot HTTP %d", resp.status)


async def async_live_stream_creds(
    hass: HomeAssistant, token: str, home_id: str, device_id: str
) -> dict[str, Any]:
    session = async_get_clientsession(hass, verify_ssl=False)
    async with session.post(
        HUE_LIVE_STREAM_URL.format(home_id=home_id),
        headers=_auth(token),
        json={"device_id_list": [device_id]},
    ) as resp:
        resp.raise_for_status()
        return await resp.json()


# ── AWS SigV4 ────────────────────────────────────────────────────────────────

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def _sigv4_headers(
    method: str, url: str, payload: bytes, region: str, ak: str, sk: str, st: str,
    service: str = "kinesisvideo",
) -> dict[str, str]:
    now = datetime.datetime.utcnow()
    date_str = now.strftime("%Y%m%d")
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    parsed = urllib.parse.urlparse(url)
    headers = {
        "content-type": "application/json",
        "host": parsed.netloc,
        "x-amz-date": stamp,
        "x-amz-security-token": st,
    }
    signed_headers = ";".join(sorted(headers))
    canonical = "\n".join(
        [
            method,
            parsed.path or "/",
            parsed.query,
            "".join(f"{k}:{v}\n" for k, v in sorted(headers.items())),
            signed_headers,
            _sha256(payload),
        ]
    )
    scope = f"{date_str}/{region}/{service}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", stamp, scope, _sha256(canonical.encode())])
    key = _hmac(_hmac(_hmac(_hmac(f"AWS4{sk}".encode(), date_str), region), service), "aws4_request")
    signature = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    return {
        "Authorization": (
            f"AWS4-HMAC-SHA256 Credential={ak}/{scope}, SignedHeaders={signed_headers}, "
            f"Signature={signature}"
        ),
        "Content-Type": "application/json",
        "Host": parsed.netloc,
        "x-amz-date": stamp,
        "x-amz-security-token": st,
    }


async def async_signaling_endpoint(
    hass: HomeAssistant, channel_arn: str, region: str, kvs: dict[str, str]
) -> str:
    session = async_get_clientsession(hass, verify_ssl=False)
    url = (
        f"https://kinesisvideo.{region}.amazonaws.com/getSignalingChannelEndpoint"
    )
    payload = json.dumps(
        {"ChannelARN": channel_arn, "SingleMasterChannelEndpointConfiguration": {
            "Protocols": ["WSS"], "Role": "VIEWER"}}
    ).encode()
    headers = _sigv4_headers(
        "POST", url, payload, region, kvs["AccessKeyId"], kvs["SecretAccessKey"], kvs["SessionToken"]
    )
    async with session.post(url, headers=headers, data=payload) as resp:
        data = await resp.json()
    for entry in data.get("ResourceEndpointList", []):
        if entry.get("Protocol") == "WSS":
            return entry["ResourceEndpoint"]
    raise RuntimeError(f"No WSS endpoint: {data}")


def presign_wss(
    endpoint: str, channel_arn: str, client_id: str, region: str,
    ak: str, sk: str, st: str,
) -> str:
    """Presign the KVS WebSocket URL (SigV4, query string)."""
    now = datetime.datetime.utcnow()
    date_str = now.strftime("%Y%m%d")
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    host = urllib.parse.urlparse(endpoint).netloc
    scope = f"{date_str}/{region}/kinesisvideo/aws4_request"

    canonical_query = (
        "X-Amz-Algorithm=AWS4-HMAC-SHA256"
        f"&X-Amz-ChannelARN={urllib.parse.quote_plus(channel_arn)}"
        f"&X-Amz-ClientId={urllib.parse.quote_plus(client_id)}"
        f"&X-Amz-Credential={urllib.parse.quote_plus(f'{ak}/{scope}')}"
        f"&X-Amz-Date={stamp}"
        "&X-Amz-Expires=299"
        f"&X-Amz-Security-Token={urllib.parse.quote_plus(st)}"
        "&X-Amz-SignedHeaders=host"
    )
    canonical = "\n".join(
        [
            "GET",
            "/",
            canonical_query,
            f"host:{host}\n",
            "host",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ]
    )
    to_sign = "\n".join(
        ["AWS4-HMAC-SHA256", stamp, scope, _sha256(canonical.encode())]
    )
    key = _hmac(_hmac(_hmac(_hmac(f"AWS4{sk}".encode(), date_str), region), "kinesisvideo"), "aws4_request")
    signature = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    return f"{endpoint}/?{canonical_query}&X-Amz-Signature={signature}"
