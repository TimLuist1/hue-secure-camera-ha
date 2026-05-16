"""Coordinator for Hue Secure Camera — handles token refresh and stream lifecycle."""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import time
from typing import Optional

import aiohttp
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import (
    CONF_BEARER_TOKEN,
    CONF_DEVICE_MAC,
    CONF_E2EE_PASSPHRASE,
    CONF_HOME_ID,
    CONF_REFRESH_TOKEN,
    HUE_API_BASE,
    TOKEN_EXPIRY_BUFFER_SECONDS,
)
from .e2ee import E2EEKeyResult, derive_frame_key
from .webrtc_client import HueWebRTCClient, StreamFrame

_LOGGER = logging.getLogger(__name__)


def _jwt_exp(token: str) -> int:
    """Return JWT expiry timestamp (epoch seconds), or 0 on error."""
    try:
        payload_b64 = token.split(".")[1]
        pad = 4 - len(payload_b64) % 4
        payload = json.loads(base64.b64decode(payload_b64 + "=" * pad))
        return int(payload.get("exp", 0))
    except Exception:
        return 0


class HueCameraCoordinator:
    """Owns the WebRTC client and handles token lifecycle for one camera."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry_data: dict,
    ) -> None:
        self.hass = hass
        self._data = dict(entry_data)

        self._bearer: str = self._data[CONF_BEARER_TOKEN]
        self._refresh: str = self._data.get(CONF_REFRESH_TOKEN, "")
        self._home_id: str = self._data[CONF_HOME_ID]
        self._device_mac: str = self._data[CONF_DEVICE_MAC]
        self._passphrase: str = self._data.get(CONF_E2EE_PASSPHRASE, "")

        self._client: Optional[HueWebRTCClient] = None
        self._latest_frame: Optional[StreamFrame] = None
        self._e2ee_key: Optional[E2EEKeyResult] = None
        self._refresh_task: Optional[asyncio.Task] = None

    # ── Token management ──────────────────────────────────────────────────

    @property
    def bearer(self) -> str:
        return self._bearer

    def _token_expires_at(self) -> int:
        return _jwt_exp(self._bearer)

    def _token_is_expired(self) -> bool:
        exp = self._token_expires_at()
        if exp == 0:
            return False  # unknown expiry → assume valid
        return time.time() >= (exp - TOKEN_EXPIRY_BUFFER_SECONDS)

    async def refresh_token(self) -> bool:
        """Try to refresh the Bearer token using the refresh token."""
        if not self._refresh:
            _LOGGER.warning("No refresh token stored; cannot auto-refresh Bearer token")
            return False

        session = async_get_clientsession(self.hass, verify_ssl=False)
        try:
            async with session.post(
                "https://api.meethue.com/v2/oauth2/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": self._refresh,
                },
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status == 200:
                    tokens = await resp.json()
                    self._bearer = tokens["access_token"]
                    self._refresh = tokens.get("refresh_token", self._refresh)
                    _LOGGER.info("Bearer token refreshed successfully")
                    return True
                _LOGGER.warning("Token refresh HTTP %d", resp.status)
        except Exception as exc:
            _LOGGER.error("Token refresh failed: %s", exc)
        return False

    async def _token_refresh_loop(self) -> None:
        """Background loop that refreshes the token before it expires."""
        while True:
            exp = self._token_expires_at()
            if exp:
                sleep_until = exp - TOKEN_EXPIRY_BUFFER_SECONDS
                sleep_for = max(0, sleep_until - time.time())
            else:
                sleep_for = 3600  # check every hour if no known expiry

            await asyncio.sleep(sleep_for)
            await self.refresh_token()

    # ── E2EE key ──────────────────────────────────────────────────────────

    async def _resolve_e2ee_key(self, live_stream_creds: dict) -> Optional[E2EEKeyResult]:
        """Derive the FrameCryptor key from the passphrase + key envelope."""
        if not self._passphrase:
            return None

        b64_envelope = live_stream_creds.get("base64KeyEnvelope", "")
        if not b64_envelope:
            _LOGGER.debug("No base64KeyEnvelope in live-stream response")
            return None

        salt_b64 = live_stream_creds.get("e2eeSalt", "")
        if salt_b64:
            salt = base64.b64decode(salt_b64 + "==")
        else:
            # Derive salt from home_id as fallback
            salt = self._home_id.encode("utf-8")[:16].ljust(16, b"\x00")

        result = derive_frame_key(self._passphrase, salt, b64_envelope)
        if result:
            _LOGGER.info("E2EE FrameCryptor key derived successfully")
        else:
            _LOGGER.warning("E2EE key derivation failed — stream may be encrypted")
        return result

    # ── Stream lifecycle ──────────────────────────────────────────────────

    def _on_frame(self, frame: StreamFrame) -> None:
        self._latest_frame = frame

    async def start_stream(self) -> bool:
        """Start the WebRTC stream. Returns True if connection was established."""
        if self._token_is_expired():
            if not await self.refresh_token():
                _LOGGER.error("Bearer token expired and refresh failed")
                return False

        # Get live-stream credentials first (also contains E2EE envelope)
        creds = await self._fetch_live_stream_creds()
        if not creds:
            return False

        # Resolve E2EE key
        self._e2ee_key = await self._resolve_e2ee_key(creds)

        kvs_creds = creds.get("awsCredentials") or creds.get("credentials") or {}
        channel_arn = creds.get("channelArn", "")
        region = creds.get("region", "eu-west-1")
        ice_servers = HueWebRTCClient._parse_ice_servers(creds)

        self._client = HueWebRTCClient(
            home_id=self._home_id,
            device_mac=self._device_mac,
            channel_arn=channel_arn,
            aws_region=region,
            hue_bearer=self._bearer,
            kvs_credentials=kvs_creds,
            ice_servers=ice_servers,
            e2ee_key=self._e2ee_key,
            on_frame=self._on_frame,
        )

        await self._client.start()

        # Start token refresh loop
        if self._refresh_task is None or self._refresh_task.done():
            self._refresh_task = asyncio.ensure_future(self._token_refresh_loop())

        connected = await self._client.wait_connected(timeout=30)
        if connected:
            _LOGGER.info("Camera %s stream connected", self._device_mac)
        else:
            _LOGGER.warning("Camera %s stream did not connect within 30s", self._device_mac)
        return connected

    async def stop_stream(self) -> None:
        if self._client:
            await self._client.stop()
            self._client = None
        if self._refresh_task:
            self._refresh_task.cancel()
            self._refresh_task = None

    async def get_latest_frame(self) -> Optional[StreamFrame]:
        """Return the latest frame, or wait up to 5s for the next one."""
        if self._latest_frame:
            return self._latest_frame
        if self._client:
            return await self._client.get_frame(timeout=5.0)
        return None

    @property
    def is_streaming(self) -> bool:
        return self._client is not None and self._client.is_connected

    async def _fetch_live_stream_creds(self) -> Optional[dict]:
        """Fetch live-stream credentials from Hue cloud."""
        url = (
            f"{HUE_API_BASE}/security/vss/v1/home/{self._home_id}"
            f"/credentials/live-stream?turn_servers=true"
        )
        session = async_get_clientsession(self.hass, verify_ssl=False)
        try:
            async with session.post(
                url,
                headers={
                    "Authorization": f"Bearer {self._bearer}",
                    "Content-Type": "application/json",
                },
                json={"device_id_list": [self._device_mac]},
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    _LOGGER.debug("live-stream creds: %s", list(data.keys()))
                    return data
                _LOGGER.warning("live-stream creds HTTP %d", resp.status)
        except Exception as exc:
            _LOGGER.error("live-stream creds error: %s", exc)
        return None
