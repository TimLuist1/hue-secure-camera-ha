"""Config flow for the Hue Secure Camera integration."""
from __future__ import annotations

import logging
import urllib.parse
from typing import Any, Optional

import voluptuous as vol
from homeassistant.config_entries import ConfigEntry, ConfigFlow, OptionsFlow
from homeassistant.core import callback
from homeassistant.data_entry_flow import FlowResult

from . import api
from .const import (
    CONF_BEARER_TOKEN,
    CONF_DEVICE_MAC,
    CONF_DEVICE_NAME,
    CONF_E2EE_PASSPHRASE,
    CONF_HOME_ID,
    CONF_REFRESH_TOKEN,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)


class HueSecureCameraConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1

    def __init__(self) -> None:
        self._verifier = ""
        self._tokens: dict[str, Any] = {}
        self._home_id = ""
        self._cameras: list[dict[str, str]] = []

    async def async_step_user(self, user_input: Optional[dict[str, Any]] = None) -> FlowResult:
        return await self.async_step_auth(user_input)

    async def async_step_auth(self, user_input: Optional[dict[str, Any]] = None) -> FlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                query = urllib.parse.parse_qs(
                    urllib.parse.urlparse(user_input["callback_url"].strip()).query
                )
                code = query.get("code", [None])[0]
                if not code:
                    raise ValueError("Kein ?code= in der URL")
                self._tokens = await api.async_exchange_code(self.hass, code, self._verifier)
                return await self.async_step_home()
            except Exception as exc:
                _LOGGER.warning("auth failed: %s", exc)
                errors["base"] = "auth_failed"

        if not self._verifier:
            self._verifier = api.make_pkce()[0]
        return self.async_show_form(
            step_id="auth",
            description_placeholders={
                "url": api.build_auth_url(self._verifier),
                "portal": "https://account.meethue.com/homes",
            },
            data_schema=vol.Schema({vol.Required("callback_url"): str}),
            errors=errors,
        )

    async def async_step_home(self, user_input: Optional[dict[str, Any]] = None) -> FlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            home_id = user_input[CONF_HOME_ID].strip()
            try:
                self._cameras = await api.async_get_devices(
                    self.hass, self._tokens["access_token"], home_id
                )
                if not self._cameras:
                    errors["base"] = "no_cameras"
                else:
                    self._home_id = home_id
                    return await self.async_step_camera()
            except Exception as exc:
                _LOGGER.warning("device list failed: %s", exc)
                errors["base"] = "cannot_connect"

        return self.async_show_form(
            step_id="home",
            description_placeholders={"portal": "https://account.meethue.com/homes"},
            data_schema=vol.Schema({vol.Required(CONF_HOME_ID, default=self._home_id): str}),
            errors=errors,
        )

    async def async_step_camera(self, user_input: Optional[dict[str, Any]] = None) -> FlowResult:
        if user_input is not None:
            mac = user_input[CONF_DEVICE_MAC]
            name = next((c["name"] for c in self._cameras if c["id"] == mac), mac)
            await self.async_set_unique_id(f"{self._home_id}_{mac}")
            self._abort_if_unique_id_configured()

            return self.async_create_entry(
                title=name,
                data={
                    CONF_HOME_ID: self._home_id,
                    CONF_DEVICE_MAC: mac,
                    CONF_DEVICE_NAME: name,
                    CONF_BEARER_TOKEN: self._tokens["access_token"],
                    CONF_REFRESH_TOKEN: self._tokens.get("refresh_token", ""),
                    CONF_E2EE_PASSPHRASE: "",
                },
            )

        options = {c["id"]: f"{c['name']} ({c['id']})" for c in self._cameras}
        return self.async_show_form(
            step_id="camera",
            data_schema=vol.Schema({vol.Required(CONF_DEVICE_MAC): vol.In(options)}),
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        return HueSecureCameraOptionsFlow(config_entry)


class HueSecureCameraOptionsFlow(OptionsFlow):
    def __init__(self, config_entry: ConfigEntry) -> None:
        self.config_entry = config_entry
        self._verifier = api.make_pkce()[0]

    async def async_step_init(self, user_input: Optional[dict[str, Any]] = None) -> FlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            data = dict(self.config_entry.data)
            if user_input.get("callback_url"):
                try:
                    query = urllib.parse.parse_qs(
                        urllib.parse.urlparse(user_input["callback_url"].strip()).query
                    )
                    code = query.get("code", [None])[0]
                    if not code:
                        raise ValueError("Kein ?code= in der URL")
                    tokens = await api.async_exchange_code(self.hass, code, self._verifier)
                    data[CONF_BEARER_TOKEN] = tokens["access_token"]
                    if tokens.get("refresh_token"):
                        data[CONF_REFRESH_TOKEN] = tokens["refresh_token"]
                except Exception as exc:
                    _LOGGER.warning("reauth failed: %s", exc)
                    errors["base"] = "auth_failed"
            data[CONF_E2EE_PASSPHRASE] = user_input.get(CONF_E2EE_PASSPHRASE, "")
            if not errors:
                self.hass.config_entries.async_update_entry(self.config_entry, data=data)
                return self.async_create_entry(title="", data={})

        return self.async_show_form(
            step_id="init",
            description_placeholders={"url": api.build_auth_url(self._verifier)},
            data_schema=vol.Schema(
                {
                    vol.Optional("callback_url", default=""): str,
                    vol.Optional(
                        CONF_E2EE_PASSPHRASE,
                        default=self.config_entry.data.get(CONF_E2EE_PASSPHRASE, ""),
                    ): str,
                }
            ),
            errors=errors,
        )
