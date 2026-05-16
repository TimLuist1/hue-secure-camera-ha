"""Config flow for Philips Hue Secure Camera."""
from __future__ import annotations

import base64
import hashlib
import logging
import os
import urllib.parse
from typing import Any

import aiohttp
import voluptuous as vol

from homeassistant import config_entries
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import (
    CONF_BEARER_TOKEN,
    CONF_DEVICE_MAC,
    CONF_DEVICE_NAME,
    CONF_E2EE_PASSPHRASE,
    CONF_HOME_ID,
    CONF_REFRESH_TOKEN,
    DOMAIN,
    HUE_API_BASE,
)

_LOGGER = logging.getLogger(__name__)

_AUTH0_DOMAIN  = "auth.meethue.com"
_CLIENT_ID     = "xOFEN65uPEwp0aMlJ6JA1CK2slFyZtGQ"
_REDIRECT_URI  = "https://account.meethue.com/"
_TOKEN_URL     = f"https://{_AUTH0_DOMAIN}/oauth/token"
_AUTHORIZE_URL = f"https://{_AUTH0_DOMAIN}/authorize"
_AUDIENCE      = "https://api.meethue.com"
_SCOPE         = "openid offline_access"


def _pkce_pair() -> tuple[str, str]:
    verifier  = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    digest    = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


def _build_auth_url(challenge: str, state: str) -> str:
    params = {
        "client_id":             _CLIENT_ID,
        "redirect_uri":          _REDIRECT_URI,
        "response_type":         "code",
        "scope":                 _SCOPE,
        "audience":              _AUDIENCE,
        "code_challenge":        challenge,
        "code_challenge_method": "S256",
        "state":                 state,
    }
    return f"{_AUTHORIZE_URL}?" + urllib.parse.urlencode(params)


def _extract_code(url: str) -> tuple[str | None, str | None]:
    try:
        qs    = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        code  = qs.get("code",  [None])[0]
        state = qs.get("state", [None])[0]
        return code, state
    except Exception:
        return None, None


async def _exchange_code(session: aiohttp.ClientSession, code: str, verifier: str) -> dict | None:
    try:
        async with session.post(
            _TOKEN_URL,
            data={
                "grant_type":    "authorization_code",
                "client_id":     _CLIENT_ID,
                "code":          code,
                "redirect_uri":  _REDIRECT_URI,
                "code_verifier": verifier,
            },
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            data = await resp.json()
            if resp.status == 200 and "access_token" in data:
                return data
            _LOGGER.debug("token exchange %s: %s", resp.status, data)
    except Exception as exc:
        _LOGGER.debug("token exchange error: %s", exc)
    return None


async def _get_homes(session: aiohttp.ClientSession, bearer: str) -> list[dict]:
    for url in [
        f"{HUE_API_BASE}/security/vss/v1/homes",
        f"{HUE_API_BASE}/data/v1/homes",
    ]:
        try:
            async with session.get(
                url,
                headers={"Authorization": f"Bearer {bearer}"},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 200:
                    data  = await resp.json()
                    homes = data.get("homes", data if isinstance(data, list) else [])
                    if homes:
                        return homes
        except Exception as exc:
            _LOGGER.debug("homes %s: %s", url, exc)
    return []


async def _get_cameras(session: aiohttp.ClientSession, bearer: str, home_id: str) -> list[dict]:
    url = f"{HUE_API_BASE}/security/device-configuration/v1/home/{home_id}/devices"
    try:
        async with session.get(
            url,
            headers={"Authorization": f"Bearer {bearer}"},
            timeout=aiohttp.ClientTimeout(total=10),
        ) as resp:
            if resp.status == 200:
                data    = await resp.json()
                devices = data if isinstance(data, list) else data.get("devices", [])
                return [
                    d for d in devices
                    if "CMW" in d.get("model_id", "")
                    or "camera" in d.get("type", "").lower()
                    or "camera" in d.get("product_name", "").lower()
                ]
    except Exception as exc:
        _LOGGER.debug("cameras: %s", exc)
    return []


class HueSecureCameraConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Config flow — OAuth2 login via Philips Hue account."""

    VERSION = 1

    def __init__(self) -> None:
        self._verifier: str      = ""
        self._state: str         = ""
        self._auth_url: str      = ""
        self._bearer: str        = ""
        self._refresh: str       = ""
        self._home_id: str       = ""
        self._cameras: list[dict] = []
        self._selected_mac: str  = ""

    # Step 1 — show login link ────────────────────────────────────────────

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        errors: dict[str, str] = {}

        if not self._verifier:
            self._verifier, challenge = _pkce_pair()
            self._state    = base64.urlsafe_b64encode(os.urandom(12)).decode().rstrip("=")
            self._auth_url = _build_auth_url(challenge, self._state)

        if user_input is not None:
            code, returned_state = _extract_code(user_input.get("callback_url", "").strip())
            if not code:
                errors["callback_url"] = "no_code"
            elif returned_state and returned_state != self._state:
                errors["callback_url"] = "state_mismatch"
            else:
                session = async_get_clientsession(self.hass)
                tokens  = await _exchange_code(session, code, self._verifier)
                if not tokens:
                    errors["callback_url"] = "token_exchange_failed"
                else:
                    self._bearer  = tokens["access_token"]
                    self._refresh = tokens.get("refresh_token", "")
                    return await self.async_step_home()

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema({"callback_url": str}),
            errors=errors,
            description_placeholders={"auth_url": self._auth_url},
        )

    # Step 2 — select home ────────────────────────────────────────────────

    async def async_step_home(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        session = async_get_clientsession(self.hass)

        if user_input is not None:
            self._home_id = user_input[CONF_HOME_ID]
            self._cameras = await _get_cameras(session, self._bearer, self._home_id)
            return await self.async_step_camera()

        homes = await _get_homes(session, self._bearer)
        if not homes:
            return await self.async_step_manual_home()

        home_options = {
            str(h.get("id", h.get("home_id", ""))): h.get("name", str(h.get("id", "")))
            for h in homes
        }
        return self.async_show_form(
            step_id="home",
            data_schema=vol.Schema({vol.Required(CONF_HOME_ID): vol.In(home_options)}),
        )

    async def async_step_manual_home(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        session = async_get_clientsession(self.hass)

        if user_input is not None:
            self._home_id = user_input[CONF_HOME_ID].strip()
            self._cameras = await _get_cameras(session, self._bearer, self._home_id)
            return await self.async_step_camera()

        return self.async_show_form(
            step_id="manual_home",
            data_schema=vol.Schema({vol.Required(CONF_HOME_ID): str}),
            description_placeholders={
                "hint": "Home-ID aus der Hue App (14-stellige Zahl, z.B. 4618484926709760)."
            },
        )

    # Step 3 — select camera ──────────────────────────────────────────────

    async def async_step_camera(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        if user_input is not None:
            self._selected_mac = user_input[CONF_DEVICE_MAC].strip().upper()
            return await self.async_step_e2ee()

        if self._cameras:
            cam_options = {
                c.get("id", c.get("mac", "")): c.get("name", c.get("product_name", c.get("id", "")))
                for c in self._cameras
            }
            schema = vol.Schema({vol.Required(CONF_DEVICE_MAC): vol.In(cam_options)})
        else:
            schema = vol.Schema({
                vol.Required(CONF_DEVICE_MAC): str,
                vol.Optional(CONF_DEVICE_NAME, default="Hue Camera"): str,
            })

        return self.async_show_form(step_id="camera", data_schema=schema)

    # Step 4 — E2EE passphrase ────────────────────────────────────────────

    async def async_step_e2ee(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        if user_input is not None:
            return await self._create_entry(user_input.get(CONF_E2EE_PASSPHRASE, "").strip())

        return self.async_show_form(
            step_id="e2ee",
            data_schema=vol.Schema({vol.Optional(CONF_E2EE_PASSPHRASE, default=""): str}),
            description_placeholders={
                "info": "E2EE-Passphrase aus der Hue App (Einstellungen → Sicherheit → Videoüberwachung). Leer lassen wenn keine gesetzt."
            },
        )

    # Create entry ────────────────────────────────────────────────────────

    async def _create_entry(self, passphrase: str) -> FlowResult:
        mac      = self._selected_mac
        cam_name = next(
            (c.get("name", c.get("product_name", mac)) for c in self._cameras if c.get("id") == mac or c.get("mac") == mac),
            f"Hue Camera {mac}",
        )
        await self.async_set_unique_id(f"{self._home_id}_{mac}")
        self._abort_if_unique_id_configured()

        return self.async_create_entry(
            title=cam_name,
            data={
                CONF_BEARER_TOKEN:   self._bearer,
                CONF_REFRESH_TOKEN:  self._refresh,
                CONF_HOME_ID:        self._home_id,
                CONF_DEVICE_MAC:     mac,
                CONF_DEVICE_NAME:    cam_name,
                CONF_E2EE_PASSPHRASE: passphrase,
            },
        )

    @staticmethod
    def async_get_options_flow(entry: config_entries.ConfigEntry) -> HueSecureCameraOptionsFlow:
        return HueSecureCameraOptionsFlow(entry)


class HueSecureCameraOptionsFlow(config_entries.OptionsFlow):
    """Re-login or update E2EE passphrase."""

    def __init__(self, entry: config_entries.ConfigEntry) -> None:
        self._entry    = entry
        self._verifier = ""
        self._state    = ""
        self._auth_url = ""

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        if user_input is not None:
            if user_input.get("action") == "relogin":
                return await self.async_step_relogin()
            return self.async_create_entry(
                title="",
                data={CONF_E2EE_PASSPHRASE: user_input.get(CONF_E2EE_PASSPHRASE, "")},
            )

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema({
                vol.Required("action", default="passphrase"): vol.In({
                    "passphrase": "Nur Passphrase aktualisieren",
                    "relogin":    "Neu einloggen (neuer Token)",
                }),
                vol.Optional(CONF_E2EE_PASSPHRASE, default=self._entry.data.get(CONF_E2EE_PASSPHRASE, "")): str,
            }),
        )

    async def async_step_relogin(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        errors: dict[str, str] = {}

        if not self._verifier:
            self._verifier, challenge = _pkce_pair()
            self._state    = base64.urlsafe_b64encode(os.urandom(12)).decode().rstrip("=")
            self._auth_url = _build_auth_url(challenge, self._state)

        if user_input is not None:
            code, _ = _extract_code(user_input.get("callback_url", "").strip())
            if not code:
                errors["callback_url"] = "no_code"
            else:
                session = async_get_clientsession(self.hass)
                tokens  = await _exchange_code(session, code, self._verifier)
                if not tokens:
                    errors["callback_url"] = "token_exchange_failed"
                else:
                    return self.async_create_entry(
                        title="",
                        data={
                            CONF_BEARER_TOKEN:  tokens["access_token"],
                            CONF_REFRESH_TOKEN: tokens.get("refresh_token", ""),
                        },
                    )

        return self.async_show_form(
            step_id="relogin",
            data_schema=vol.Schema({"callback_url": str}),
            errors=errors,
            description_placeholders={"auth_url": self._auth_url},
        )
