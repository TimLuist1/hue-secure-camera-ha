"""MJPEG stream view (token in path so <img> works without headers)."""
from __future__ import annotations

import asyncio
import logging

from aiohttp import web
from homeassistant.components.http import HomeAssistantView

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

MJPEG_CLIENTS: set[asyncio.Queue] = set()


class HueCameraMJPEGView(HomeAssistantView):
    url = "/api/hue_secure_camera/stream/{token}/{entry_id}"
    name = "api:hue_secure_camera:stream"
    requires_auth = False

    async def get(self, request: web.Request, token: str, entry_id: str) -> web.StreamResponse:
        hass = request.app["hass"]
        data = hass.data.get(DOMAIN, {})
        if token != data.get("token"):
            return web.Response(status=401, text="invalid token")
        coordinator = data.get(entry_id)
        if coordinator is None:
            return web.Response(status=404, text="unknown camera")

        resp = web.StreamResponse(
            headers={
                "Content-Type": "multipart/x-mixed-replace; boundary=frame",
                "Cache-Control": "no-store",
                "Connection": "close",
            }
        )
        await resp.prepare(request)
        last = None
        try:
            while True:
                frame = await coordinator.async_frame(timeout=4)
                if frame and frame is not last:
                    last = frame
                    await resp.write(
                        b"--frame\r\nContent-Type: image/jpeg\r\nContent-Length: "
                        + str(len(frame)).encode()
                        + b"\r\n\r\n"
                        + frame
                        + b"\r\n"
                    )
                else:
                    await asyncio.sleep(0.1)
        except (asyncio.CancelledError, ConnectionResetError):
            pass
        return resp
