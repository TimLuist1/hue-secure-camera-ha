"""Config flow for Philips Hue Secure Camera."""
from __future__ import annotations

import base64
import json
import logging
import re
from typing import Any

import aiohttp
import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_NAME
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import (
    CONF_BEARER_TOKEN,
    CONF_BRIDGE_IP,
    CONF_BRIDGE_KEY,
    CONF_CHANNEL_ARN,
    CONF_DEVICE_MAC,
    CONF_DEVICE_NAME,
    CONF_E2EE_PASSPHRASE,
    CONF_HOME_ID,
    CONF_REFRESH_TOKEN,
    DOMAIN,
    HUE_API_BASE,
)

_LOGGER = logging.getLogger(__name__)


# ─── helpers ──────────────────────────────────────────────────────────────────

def _jwt_payload(token: str) -> dict:
    """Decode JWT payload without verification."""
    try:
        payload_b64 = token.split(".")[1]
        pad = 4 - len(payload_b64) % 4
        return json.loads(base64.b64decode(payload_b64 + "=" * pad))
    except Exception:
        return {}


async def _get_homes(session: aiohttp.ClientSession, bearer: str) -> list[dict]:
    """Fetch all homes from the Hue security API."""
    url = f"{HUE_API_BASE}/security/vss/v1/homes"
    try:
        async with session.get(
            url,
            headers={"Authorization": f"Bearer {bearer}"},
            ssl=False,
            timeout=aiohttp.ClientTimeout(total=10),
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                return data.get("homes", data if isinstance(data, list) else [])
    except Exception as exc:
        _LOGGER.debug("homes fetch error: %s", exc)
    return []


async def _get_cameras(
    session: aiohttp.ClientSession, bearer: str, home_id: str
) -> list[dict]:
    """Fetch camera list for a home."""
    url = f"{HUE_API_BASE}/security/device-configuration/v1/home/{home_id}/devices"
    try:
        async with session.get(
            url,
            headers={"Authorization": f"Bearer {bearer}"},
            ssl=False,
            timeout=aiohttp.ClientTimeout(total=10),
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                devices = data if isinstance(data, list) else data.get("devices", [])
                return [
                    d for d in devices
                    if "CMW" in d.get("model_id", "") or "camera" in d.get("type", "").lower()
                ]
    except Exception as exc:
        _LOGGER.debug("devices fetch error: %s", exc)
    return []


async def _get_live_stream_creds(
    session: aiohttp.ClientSession, bearer: str, home_id: str, device_mac: str
) -> dict | None:
    """Fetch KVS signaling credentials."""
    url = (
        f"{HUE_API_BASE}/security/vss/v1/home/{home_id}"
        f"/credentials/live-stream?turn_servers=true"
    )
    try:
        async with session.post(
            url,
            headers={
                "Authorization": f"Bearer {bearer}",
                "Content-Type": "application/json",
            },
            json={"device_id_list": [device_mac]},
            ssl=False,
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            if resp.status == 200:
                return await resp.json()
    except Exception as exc:
        _LOGGER.debug("live-stream creds error: %s", exc)
    return None


# ─── Flow ─────────────────────────────────────────────────────────────────────

class HueSecureCameraConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle config flow for Hue Secure Camera."""

    VERSION = 1

    def __init__(self) -> None:
        self._bearer: str = ""
        self._refresh: str = ""
        self._home_id: str = ""
        self._home_name: str = ""
        self._cameras: list[dict] = []
        self._selected_mac: str = ""
        self._bridge_ip: str = ""
        self._bridge_key: str = ""

    # ── Step 1 · bearer token ──────────────────────────────────────────────

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Step 1: Enter Hue Bearer token."""
        errors: dict[str, str] = {}

        if user_input is not None:
            bearer = user_input[CONF_BEARER_TOKEN].strip()
            payload = _jwt_payload(bearer)

            if not payload:
                errors[CONF_BEARER_TOKEN] = "invalid_token"
            else:
                self._bearer = bearer
                self._refresh = user_input.get(CONF_REFRESH_TOKEN, "").strip()
                return await self.async_step_home()

        schema = vol.Schema(
            {
                vol.Required(CONF_BEARER_TOKEN): str,
                vol.Optional(CONF_REFRESH_TOKEN, default=""): str,
            }
        )
        return self.async_show_form(
            step_id="user",
            data_schema=schema,
            errors=errors,
            description_placeholders={
                "howto": (
                    "Öffne die Philips Hue App auf deinem Handy mit einem "
                    "Man-in-the-Middle-Proxy (z.B. mitmproxy / Charles) und kopiere "
                    "den 'Authorization: Bearer …' Header aus einem API-Request. "
                    "Optional: Refresh Token für automatische Erneuerung."
                )
            },
        )

    # ── Step 2 · select home ──────────────────────────────────────────────

    async def async_step_home(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Step 2: Select Hue Home."""
        errors: dict[str, str] = {}
        session = async_get_clientsession(self.hass, verify_ssl=False)

        if user_input is not None:
            home_id = user_input["home_id"]
            self._home_id = home_id
            # fetch cameras for this home
            self._cameras = await _get_cameras(session, self._bearer, home_id)
            if not self._cameras:
                errors["home_id"] = "no_cameras"
            else:
                return await self.async_step_camera()

        homes = await _get_homes(session, self._bearer)
        if not homes:
            # Fall back: try to parse home_id from JWT sub or ask manually
            return await self.async_step_manual_home()

        home_options = {h.get("id", ""): h.get("name", h.get("id", "")) for h in homes}
        schema = vol.Schema({vol.Required("home_id"): vol.In(home_options)})
        return self.async_show_form(
            step_id="home",
            data_schema=schema,
            errors=errors,
        )

    async def async_step_manual_home(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Fallback: enter home_id manually."""
        errors: dict[str, str] = {}
        session = async_get_clientsession(self.hass, verify_ssl=False)

        if user_input is not None:
            home_id = user_input[CONF_HOME_ID].strip()
            self._home_id = home_id
            self._cameras = await _get_cameras(session, self._bearer, home_id)
            if not self._cameras:
                # Try to proceed with MAC given directly
                return await self.async_step_camera()
            return await self.async_step_camera()

        schema = vol.Schema({vol.Required(CONF_HOME_ID): str})
        return self.async_show_form(
            step_id="manual_home",
            data_schema=schema,
            errors=errors,
            description_placeholders={
                "hint": "Die Home-ID findest du in der URL der Hue App (14-stellige Zahl)."
            },
        )

    # ── Step 3 · select camera ────────────────────────────────────────────

    async def async_step_camera(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Step 3: Choose which camera to add."""
        errors: dict[str, str] = {}

        if user_input is not None:
            self._selected_mac = user_input[CONF_DEVICE_MAC].strip().upper()
            return await self.async_step_e2ee()

        if self._cameras:
            cam_options = {
                c.get("id", c.get("mac", "")): c.get("name", c.get("id", ""))
                for c in self._cameras
            }
            schema = vol.Schema(
                {vol.Required(CONF_DEVICE_MAC): vol.In(cam_options)}
            )
        else:
            schema = vol.Schema(
                {
                    vol.Required(CONF_DEVICE_MAC): str,
                    vol.Optional(CONF_DEVICE_NAME, default="Hue Camera"): str,
                }
            )

        return self.async_show_form(
            step_id="camera",
            data_schema=schema,
            errors=errors,
        )

    # ── Step 4 · E2EE passphrase ──────────────────────────────────────────

    async def async_step_e2ee(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Step 4: E2EE passphrase (optional)."""
        if user_input is not None:
            passphrase = user_input.get(CONF_E2EE_PASSPHRASE, "").strip()
            return await self._create_entry(passphrase)

        schema = vol.Schema(
            {
                vol.Optional(CONF_E2EE_PASSPHRASE, default=""): str,
            }
        )
        return self.async_show_form(
            step_id="e2ee",
            data_schema=schema,
            description_placeholders={
                "info": (
                    "Falls du in der Hue App unter Einstellungen → Sicherheit → "
                    "Videoüberwachung eine E2EE-Passphrase eingerichtet hast, "
                    "trage sie hier ein. Sie wird für die Videoentschlüsselung "
                    "benötigt. Leer lassen wenn keine gesetzt."
                )
            },
        )

    # ── Final: create entry ───────────────────────────────────────────────

    async def _create_entry(self, passphrase: str) -> FlowResult:
        """Create the config entry."""
        mac = self._selected_mac
        cam_name = next(
            (
                c.get("name", mac)
                for c in self._cameras
                if c.get("id") == mac or c.get("mac") == mac
            ),
            mac,
        )

        await self.async_set_unique_id(f"{self._home_id}_{mac}")
        self._abort_if_unique_id_configured()

        return self.async_create_entry(
            title=cam_name or f"Hue Camera {mac}",
            data={
                CONF_BEARER_TOKEN: self._bearer,
                CONF_REFRESH_TOKEN: self._refresh,
                CONF_HOME_ID: self._home_id,
                CONF_DEVICE_MAC: mac,
                CONF_DEVICE_NAME: cam_name,
                CONF_E2EE_PASSPHRASE: passphrase,
            },
        )

    # ── Options flow ──────────────────────────────────────────────────────

    @staticmethod
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> HueSecureCameraOptionsFlow:
        return HueSecureCameraOptionsFlow(config_entry)


class HueSecureCameraOptionsFlow(config_entries.OptionsFlow):
    """Allow updating bearer token and passphrase."""

    def __init__(self, entry: config_entries.ConfigEntry) -> None:
        self._entry = entry

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        schema = vol.Schema(
            {
                vol.Required(
                    CONF_BEARER_TOKEN,
                    default=self._entry.data.get(CONF_BEARER_TOKEN, ""),
                ): str,
                vol.Optional(
                    CONF_REFRESH_TOKEN,
                    default=self._entry.data.get(CONF_REFRESH_TOKEN, ""),
                ): str,
                vol.Optional(
                    CONF_E2EE_PASSPHRASE,
                    default=self._entry.data.get(CONF_E2EE_PASSPHRASE, ""),
                ): str,
            }
        )
        return self.async_show_form(step_id="init", data_schema=schema)
