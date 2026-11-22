"""Coordinator: token lifecycle, browser-assisted WebRTC sessions, latest frame."""
from __future__ import annotations

import asyncio
import base64
import logging
import time
from typing import Any, Optional

import aiohttp
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from . import api
from .const import CONF_BEARER_TOKEN, CONF_DEVICE_MAC, CONF_HOME_ID, CONF_REFRESH_TOKEN, FRAME_MAX_AGE_SECONDS

_LOGGER = logging.getLogger(__name__)


class HueCameraCoordinator:
    """Owns tokens and one optional signaling session for a camera."""

    def __init__(self, hass: HomeAssistant, entry_id: str, data: dict[str, Any]) -> None:
        self.hass = hass
        self.entry_id = entry_id
        self._data = dict(data)
        self._session: Optional[SignalingSession] = None
        self._latest_frame: Optional[bytes] = None
        self._last_frame_at: float = 0.0
        self._refresh_task: Optional[asyncio.Task] = None

    # ── tokens ───────────────────────────────────────────────────────────

    @property
    def token(self) -> str:
        return self._data.get(CONF_BEARER_TOKEN, "")

    @property
    def home_id(self) -> str:
        return self._data[CONF_HOME_ID]

    @property
    def device_mac(self) -> str:
        return self._data[CONF_DEVICE_MAC]

    async def async_ensure_token(self) -> bool:
        if not api.token_needs_refresh(self.token):
            return True
        refresh = self._data.get(CONF_REFRESH_TOKEN, "")
        if not refresh:
            return True
        tokens = await api.async_refresh(self.hass, refresh)
        if not tokens:
            _LOGGER.error("Hue token refresh failed")
            return False
        self._data[CONF_BEARER_TOKEN] = tokens["access_token"]
        if tokens.get("refresh_token"):
            self._data[CONF_REFRESH_TOKEN] = tokens["refresh_token"]
        return True

    def async_start_refresh_loop(self) -> None:
        async def _loop() -> None:
            while True:
                await asyncio.sleep(3600)
                await self.async_ensure_token()

        self._refresh_task = self.hass.async_create_background_task(
            _loop(), f"hue_secure_camera refresh {self.entry_id}"
        )

    def async_stop(self) -> None:
        if self._refresh_task:
            self._refresh_task.cancel()
        if self._session:
            self._session.async_stop()

    # ── frames ───────────────────────────────────────────────────────────

    def push_frame(self, jpeg: bytes) -> None:
        self._latest_frame = jpeg
        self._last_frame_at = time.monotonic()

    @property
    def latest_frame(self) -> Optional[bytes]:
        if self._latest_frame and time.monotonic() - self._last_frame_at < FRAME_MAX_AGE_SECONDS:
            return self._latest_frame
        return self._latest_frame

    @property
    def is_streaming(self) -> bool:
        return bool(self._latest_frame) and time.monotonic() - self._last_frame_at < FRAME_MAX_AGE_SECONDS

    # ── sessions ─────────────────────────────────────────────────────────

    async def async_start_session(self, connection, msg_id: int) -> dict[str, Any]:
        await self.async_stop_session()
        session = SignalingSession(self, connection, msg_id)
        await session.async_start()
        self._session = session
        return {"session": session.session_id, "iceServers": session.ice_servers}

    async def async_stop_session(self) -> None:
        if self._session:
            await self._session.async_stop()
            self._session = None


class SignalingSession:
    """One KVS signaling session between camera and a browser viewer."""

    def __init__(self, coordinator: HueCameraCoordinator, connection, msg_id: int) -> None:
        self.coordinator = coordinator
        self.hass = coordinator.hass
        self.connection = connection
        self.msg_id = msg_id
        self.session_id = base64.urlsafe_b64encode(__import__("os").urandom(9)).decode().rstrip("=")
        self.ice_servers: list[dict[str, Any]] = []
        self._ws: Optional[aiohttp.ClientWebSocketResponse] = None
        self._tasks: list[asyncio.Task] = []
        self._remote_id = ""
        self._answered = asyncio.Event()
        self._last_offer: Optional[str] = None
        self._stopped = False
        self._wake_task: Optional[asyncio.Task] = None

    # event helper
    def _emit(self, payload: dict[str, Any]) -> None:
        payload["session"] = self.session_id
        try:
            from homeassistant.components import websocket_api

            self.connection.send_message(websocket_api.event_message(self.msg_id, payload))
        except Exception as exc:  # connection gone
            _LOGGER.debug("emit failed: %s", exc)

    async def async_start(self) -> None:
        coordinator = self.coordinator
        if not await coordinator.async_ensure_token():
            raise RuntimeError("Token abgelaufen")

        creds = await api.async_live_stream_creds(
            self.hass, coordinator.token, coordinator.home_id, coordinator.device_mac
        )
        await self._setup_signaling(creds)
        await api.async_wake(
            self.hass, coordinator.token, coordinator.home_id, coordinator.device_mac
        )
        self._wake_task = self.hass.async_create_background_task(
            self._wake_loop(), f"hue wake {self.session_id}"
        )

    async def _setup_signaling(self, creds: dict[str, Any]) -> None:
        coordinator = self.coordinator
        raw = creds.get("credentials") or creds.get("awsCredentials") or {}
        kvs = {
            "AccessKeyId": raw.get("AccessKeyId", ""),
            "SecretAccessKey": raw.get("SecretAccessKey", ""),
            "SessionToken": raw.get("SessionToken", ""),
        }
        arn = creds.get("channelArn") or creds["signaling_channels"][0]["arn"]
        region = arn.split(":")[3] if arn.count(":") >= 3 else "eu-west-1"

        for turn in creds.get("turn_servers", []):
            for srv in turn.get("ice_servers", []):
                self.ice_servers.append(
                    {
                        "urls": srv.get("urls"),
                        "username": srv.get("username"),
                        "credential": srv.get("password"),
                    }
                )
        for stun in creds.get("stun_servers", []):
            self.ice_servers.append({"urls": stun})

        endpoint = await api.async_signaling_endpoint(self.hass, arn, region, kvs)
        client_id = f"HA-{coordinator.device_mac}-{int(time.time())}"
        url = api.presign_wss(
            endpoint, arn, client_id, region,
            kvs["AccessKeyId"], kvs["SecretAccessKey"], kvs["SessionToken"],
        )
        session = async_get_clientsession(self.hass, verify_ssl=False)
        self._ws = await session.ws_connect(url, headers={"User-Agent": "HomeAssistant/HueCamera"})
        self._tasks.append(
            self.hass.async_create_background_task(
                self._kvs_loop(), f"hue kvs {self.session_id}"
            )
        )
        self._emit({"type": "ready", "iceServers": self.ice_servers})

    async def _kvs_loop(self) -> None:
        from . import signal

        assert self._ws
        async for msg in self._ws:
            if msg.type != aiohttp.WSMsgType.TEXT:
                continue
            action, payload, sender = signal.decode_kvs(msg.data)
            if action == "SDP_ANSWER" or payload.get("type") == "answer":
                self._remote_id = sender or self._remote_id
                self._answered.set()
                self._emit({"type": "answer", "sdp": payload.get("sdp", "")})
            elif action == "SDP_OFFER":
                self._remote_id = sender or self._remote_id
                self._emit({"type": "offer", "sdp": payload.get("sdp", "")})
            elif action == "ICE_CANDIDATE":
                self._emit(
                    {
                        "type": "ice",
                        "candidate": payload.get("candidate", ""),
                        "sdpMid": payload.get("sdpMid", "0"),
                        "sdpMLineIndex": payload.get("sdpMLineIndex", 0),
                    }
                )

    async def _wake_loop(self) -> None:
        tick = 0
        while not self._stopped:
            await asyncio.sleep(8)
            tick += 1
            try:
                await api.async_wake(
                    self.hass, self.coordinator.token, self.coordinator.home_id, self.coordinator.device_mac
                )
                if self._answered.is_set():
                    continue
                if self._last_offer and self._ws and not self._ws.closed:
                    from . import signal

                    await self._ws.send_str(
                        signal.encode_kvs(
                            "SDP_OFFER", {"sdp": self._last_offer, "type": "offer"}
                        )
                    )
            except Exception as exc:
                _LOGGER.debug("wake loop: %s", exc)

    # browser → camera
    async def async_send_offer(self, sdp: str) -> None:
        from . import signal

        self._last_offer = sdp
        if self._ws:
            await self._ws.send_str(signal.encode_kvs("SDP_OFFER", {"sdp": sdp, "type": "offer"}))

    async def async_send_answer(self, sdp: str) -> None:
        from . import signal

        if self._ws:
            await self._ws.send_str(
                signal.encode_kvs("SDP_ANSWER", {"sdp": sdp, "type": "answer"}, self._remote_id)
            )

    async def async_send_ice(self, candidate: str, sdp_mid: str, index: int) -> None:
        from . import signal

        if self._ws:
            await self._ws.send_str(
                signal.encode_kvs(
                    "ICE_CANDIDATE",
                    {"candidate": candidate, "sdpMid": sdp_mid, "sdpMLineIndex": index},
                    self._remote_id,
                )
            )

    async def async_stop(self) -> None:
        self._stopped = True
        if self._wake_task:
            self._wake_task.cancel()
        for task in self._tasks:
            task.cancel()
        if self._ws:
            try:
                await self._ws.close()
            except Exception:
                pass
            self._ws = None
