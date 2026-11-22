"""KVS message helpers + Home Assistant websocket commands for signaling."""
from __future__ import annotations

import base64
import json
import logging
from typing import Any

import voluptuous as vol
from homeassistant.components import websocket_api
from homeassistant.core import HomeAssistant, callback

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


def decode_kvs(raw: Any) -> tuple[str, dict[str, Any], str]:
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    if not raw:
        return "", {}, ""
    try:
        msg = json.loads(raw)
    except json.JSONDecodeError:
        return "", {}, ""
    action = msg.get("action") or msg.get("messageType") or ""
    sender = msg.get("senderClientId", "")
    payload: dict[str, Any] = {}
    encoded = msg.get("messagePayload", "")
    if encoded:
        try:
            payload = json.loads(base64.b64decode(encoded + "=="))
        except Exception:
            payload = {}
    return action, payload, sender


def encode_kvs(action: str, payload: dict[str, Any], recipient: str = "") -> str:
    return json.dumps(
        {
            "action": action,
            "messagePayload": base64.b64encode(json.dumps(payload).encode()).decode(),
            "recipientClientId": recipient,
        }
    )


def _coordinator(hass: HomeAssistant, entry_id: str):
    return hass.data.get(DOMAIN, {}).get(entry_id)


@websocket_api.websocket_command(
    {vol.Required("type"): "hue_secure_camera/session", vol.Required("entry_id"): str}
)
@websocket_api.async_response
async def ws_session(hass, connection, msg):
    coordinator = _coordinator(hass, msg["entry_id"])
    if coordinator is None:
        connection.send_error(msg["id"], "not_found", "Kamera nicht gefunden")
        return
    try:
        result = await coordinator.async_start_session(connection, msg["id"])
    except Exception as exc:
        _LOGGER.exception("session start failed")
        connection.send_error(msg["id"], "start_failed", str(exc))
        return
    connection.send_result(msg["id"], result)
    connection.subscriptions[msg["id"]] = coordinator.async_stop_session


@websocket_api.websocket_command(
    {
        vol.Required("type"): "hue_secure_camera/offer",
        vol.Required("entry_id"): str,
        vol.Required("sdp"): str,
    }
)
@websocket_api.async_response
async def ws_offer(hass, connection, msg):
    coordinator = _coordinator(hass, msg["entry_id"])
    if coordinator and coordinator._session:
        await coordinator._session.async_send_offer(msg["sdp"])
    connection.send_result(msg["id"])


@websocket_api.websocket_command(
    {
        vol.Required("type"): "hue_secure_camera/answer",
        vol.Required("entry_id"): str,
        vol.Required("sdp"): str,
    }
)
@websocket_api.async_response
async def ws_answer(hass, connection, msg):
    coordinator = _coordinator(hass, msg["entry_id"])
    if coordinator and coordinator._session:
        await coordinator._session.async_send_answer(msg["sdp"])
    connection.send_result(msg["id"])


@websocket_api.websocket_command(
    {
        vol.Required("type"): "hue_secure_camera/ice",
        vol.Required("entry_id"): str,
        vol.Required("candidate"): str,
        vol.Optional("sdpMid", default="0"): str,
        vol.Optional("sdpMLineIndex", default=0): int,
    }
)
@websocket_api.async_response
async def ws_ice(hass, connection, msg):
    coordinator = _coordinator(hass, msg["entry_id"])
    if coordinator and coordinator._session:
        await coordinator._session.async_send_ice(
            msg["candidate"], msg["sdpMid"], msg["sdpMLineIndex"]
        )
    connection.send_result(msg["id"])


@websocket_api.websocket_command(
    {
        vol.Required("type"): "hue_secure_camera/frame",
        vol.Required("entry_id"): str,
        vol.Required("jpeg"): str,
    }
)
@callback
def ws_frame(hass, connection, msg):
    coordinator = _coordinator(hass, msg["entry_id"])
    if coordinator:
        try:
            coordinator.push_frame(base64.b64decode(msg["jpeg"]))
        except Exception:
            pass
    connection.send_result(msg["id"])


@websocket_api.websocket_command(
    {vol.Required("type"): "hue_secure_camera/stop", vol.Required("entry_id"): str}
)
@websocket_api.async_response
async def ws_stop(hass, connection, msg):
    coordinator = _coordinator(hass, msg["entry_id"])
    if coordinator:
        await coordinator.async_stop_session()
    connection.send_result(msg["id"])


@callback
def async_register_websocket(hass: HomeAssistant) -> None:
    websocket_api.async_register_command(hass, ws_session)
    websocket_api.async_register_command(hass, ws_offer)
    websocket_api.async_register_command(hass, ws_answer)
    websocket_api.async_register_command(hass, ws_ice)
    websocket_api.async_register_command(hass, ws_frame)
    websocket_api.async_register_command(hass, ws_stop)
