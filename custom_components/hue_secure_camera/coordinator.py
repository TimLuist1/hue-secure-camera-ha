"""Coordinator: token lifecycle, native stream lifecycle, frame buffer."""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Optional

from homeassistant.core import HomeAssistant

from . import api
from .const import (
    CONF_BEARER_TOKEN,
    CONF_DEVICE_MAC,
    CONF_HOME_ID,
    CONF_REFRESH_TOKEN,
    FRAME_MAX_AGE_SECONDS,
)
from .webrtc_client import HueWebRTCClient

_LOGGER = logging.getLogger(__name__)

IDLE_STOP_SECONDS = 1800


class HueCameraCoordinator:
    """Owns tokens, the stream client and the latest JPEG."""

    def __init__(self, hass: HomeAssistant, entry_id: str, data: dict[str, Any]) -> None:
        self.hass = hass
        self.entry_id = entry_id
        self._data = dict(data)
        self._latest_frame: Optional[bytes] = None
        self._last_frame_at: float = 0.0
        self._last_used = 0.0
        self._refresh_task: Optional[asyncio.Task] = None
        self._idle_task: Optional[asyncio.Task] = None
        self._client: Optional[HueWebRTCClient] = None
        self._connected = False
        self._entities: set = set()
        self._listeners: set[asyncio.Queue] = set()

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

    async def async_token(self) -> str:
        if api.token_needs_refresh(self.token):
            refresh = self._data.get(CONF_REFRESH_TOKEN, "")
            if refresh:
                tokens = await api.async_refresh(self.hass, refresh)
                if tokens:
                    self._data[CONF_BEARER_TOKEN] = tokens["access_token"]
                    if tokens.get("refresh_token"):
                        self._data[CONF_REFRESH_TOKEN] = tokens["refresh_token"]
        return self.token

    def async_start_refresh_loop(self) -> None:
        async def _loop() -> None:
            while True:
                await asyncio.sleep(3600)
                await self.async_token()

        self._refresh_task = self.hass.async_create_background_task(
            _loop(), f"hue refresh {self.entry_id}"
        )

    def async_stop(self) -> None:
        for task in (self._refresh_task, self._idle_task):
            if task:
                task.cancel()
        if self._client:
            self.hass.async_create_task(self._client.stop())

    # ── frames ───────────────────────────────────────────────────────────

    def _on_frame(self, jpeg: bytes) -> None:
        self._latest_frame = jpeg
        self._last_frame_at = time.monotonic()
        for queue in list(self._listeners):
            if queue.full():
                try:
                    queue.get_nowait()
                except Exception:
                    pass
            try:
                queue.put_nowait(jpeg)
            except Exception:
                pass
        for entity in self._entities:
            entity.async_write_ha_state()

    def _on_connected(self, connected: bool) -> None:
        self._connected = connected
        for entity in self._entities:
            entity.async_write_ha_state()

    def add_listener(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=2)
        self._listeners.add(queue)
        return queue

    def remove_listener(self, queue: asyncio.Queue) -> None:
        self._listeners.discard(queue)

    @property
    def latest_frame(self) -> Optional[bytes]:
        return self._latest_frame

    @property
    def is_streaming(self) -> bool:
        return self._connected and time.monotonic() - self._last_frame_at < FRAME_MAX_AGE_SECONDS

    # ── stream ───────────────────────────────────────────────────────────

    async def async_ensure_stream(self) -> None:
        self._last_used = time.monotonic()
        if self._client and self._client.is_alive:
            return
        if self._client is not None and self._client._running:
            await self._client.restart()
            return
        if self._client is None:
            self._client = HueWebRTCClient(
                self.hass,
                self.async_token,
                self.home_id,
                self.device_mac,
                self._on_frame,
                self._on_connected,
            )
        if not self._client._running:
            await self._client.start()
        if False and (self._idle_task is None or self._idle_task.done()):
            self._idle_task = self.hass.async_create_background_task(
                self._idle_loop(), f"hue idle {self.entry_id}"
            )

    async def _idle_loop(self) -> None:
        while True:
            await asyncio.sleep(30)
            if time.monotonic() - self._last_used > IDLE_STOP_SECONDS:
                if self._client:
                    await self._client.stop()
                return

    async def async_frame(self, timeout: float = 6.0) -> Optional[bytes]:
        await self.async_ensure_stream()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._latest_frame and time.monotonic() - self._last_frame_at < 3:
                return self._latest_frame
            await asyncio.sleep(0.15)
        return self._latest_frame
