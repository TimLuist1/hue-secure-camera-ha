"""Native HA WebRTC answerer: forwards the browser offer to the camera via KVS."""
from __future__ import annotations

import asyncio
import base64
import logging
import time
from typing import Any, Callable, Optional

import aiohttp
from homeassistant.components.camera.webrtc import (
    WebRTCAnswer,
    WebRTCCandidate,
    WebRTCClientConfiguration,
    WebRTCError,
    WebRTCSendMessage,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from webrtc_models import RTCConfiguration, RTCIceCandidateInit, RTCIceServer

from . import api, signal

_LOGGER = logging.getLogger(__name__)


class HueWebRTCBridge:
    """One browser session, bridged 1:1 to a KVS viewer session."""

    def __init__(self, hass: HomeAssistant, coordinator) -> None:
        self.hass = hass
        self.coordinator = coordinator
        self._ws: Optional[aiohttp.ClientWebSocketResponse] = None
        self._remote_id = ""
        self._send: Optional[WebRTCSendMessage] = None
        self._tasks: list[asyncio.Task] = []
        self._ice_servers: list[dict[str, Any]] = []
        self._pending_candidates: list[dict[str, Any]] = []

    async def async_prepare(self) -> WebRTCClientConfiguration:
        """Fetch credentials and build the RTCConfiguration for the client."""
        token = await self.coordinator.async_token()
        creds = await api.async_live_stream_creds(
            self.hass, token, self.coordinator.home_id, self.coordinator.device_mac
        )
        self._creds = creds
        servers: list[RTCIceServer] = []
        for entry in creds.get("turn_servers", []):
            for srv in entry.get("ice_servers", []):
                servers.append(
                    RTCIceServer(
                        urls=srv.get("urls"),
                        username=srv.get("username"),
                        credential=srv.get("password"),
                    )
                )
        for stun in creds.get("stun_servers", []):
            servers.append(RTCIceServer(urls=stun))
        return WebRTCClientConfiguration(configuration=RTCConfiguration(ice_servers=servers))

    async def async_start(self, offer_sdp: str, send_message: WebRTCSendMessage) -> None:
        self._send = send_message
        creds = self._creds
        raw = creds.get("credentials") or creds.get("awsCredentials") or {}
        kvs = {
            "AccessKeyId": raw.get("AccessKeyId", ""),
            "SecretAccessKey": raw.get("SecretAccessKey", ""),
            "SessionToken": raw.get("SessionToken", ""),
        }
        arn = creds.get("channelArn") or creds["signaling_channels"][0]["arn"]
        region = arn.split(":")[3] if arn.count(":") >= 3 else "eu-west-1"
        endpoint = await api.async_signaling_endpoint(self.hass, arn, region, kvs)
        client_id = f"HA-{self.coordinator.device_mac}-{int(time.time())}"
        url = api.presign_wss(
            endpoint, arn, client_id, region,
            kvs["AccessKeyId"], kvs["SecretAccessKey"], kvs["SessionToken"],
        )
        session = async_get_clientsession(self.hass, verify_ssl=False)
        self._ws = await session.ws_connect(url, headers={"User-Agent": "HomeAssistant/HueCamera"})
        await api.async_wake(
            self.hass, await self.coordinator.async_token(),
            self.coordinator.home_id, self.coordinator.device_mac,
        )
        self._tasks.append(
            self.hass.async_create_background_task(
                self._kvs_loop(), f"hue webrtc bridge {self.coordinator.device_mac}"
            )
        )
        await self._ws.send_str(signal.encode_kvs("SDP_OFFER", {"sdp": offer_sdp, "type": "offer"}))

    async def _kvs_loop(self) -> None:
        assert self._ws
        try:
            async for msg in self._ws:
                if msg.type != aiohttp.WSMsgType.TEXT:
                    continue
                action, payload, sender = signal.decode_kvs(msg.data)
                if action == "SDP_ANSWER" or payload.get("type") == "answer":
                    self._remote_id = sender or self._remote_id
                    if self._send:
                        self._send(WebRTCAnswer(payload.get("sdp", "")))
                    await self._flush_candidates()
                elif action == "ICE_CANDIDATE":
                    if self._send and payload.get("candidate"):
                        self._send(
                            WebRTCCandidate(
                                RTCIceCandidateInit.from_dict(
                                    {
                                        "candidate": payload["candidate"],
                                        "sdpMid": payload.get("sdpMid", "0"),
                                        "sdpMLineIndex": payload.get("sdpMLineIndex", 0),
                                    }
                                )
                            )
                        )
        except Exception as exc:
            _LOGGER.debug("bridge kvs loop ended: %s", exc)
        finally:
            if self._send:
                self._send(WebRTCError("webrtc_closed", "Stream beendet"))

    async def async_add_candidate(self, candidate: dict[str, Any]) -> None:
        self._pending_candidates.append(candidate)
        if self._ws and self._remote_id:
            await self._flush_candidates()

    async def _flush_candidates(self) -> None:
        while self._pending_candidates and self._ws:
            cand = self._pending_candidates.pop(0)
            await self._ws.send_str(
                signal.encode_kvs(
                    "ICE_CANDIDATE",
                    {
                        "candidate": cand.get("candidate", ""),
                        "sdpMid": cand.get("sdpMid", "0"),
                        "sdpMLineIndex": cand.get("sdpMLineIndex", 0),
                    },
                    self._remote_id,
                )
            )

    async def async_close(self) -> None:
        for task in self._tasks:
            task.cancel()
        if self._ws:
            try:
                await self._ws.close()
            except Exception:
                pass
            self._ws = None
