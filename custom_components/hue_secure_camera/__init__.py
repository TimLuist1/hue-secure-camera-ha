"""Philips Hue Secure Camera integration for Home Assistant."""
from __future__ import annotations

import logging
from pathlib import Path

from homeassistant.components.frontend import add_extra_js_url
from homeassistant.components.http import StaticPathConfig
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .coordinator import HueCameraCoordinator
from .signal import async_register_websocket

_LOGGER = logging.getLogger(__name__)

PLATFORMS = ["camera"]
CARD_URL = "/hue_secure_camera/hue-camera-card.js"


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    hass.data.setdefault(DOMAIN, {})
    async_register_websocket(hass)

    card_path = Path(__file__).parent / "frontend" / "hue-camera-card.js"
    await hass.http.async_register_static_paths(
        [StaticPathConfig(CARD_URL, str(card_path), cache_headers=False)]
    )
    add_extra_js_url(hass, CARD_URL)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    coordinator = HueCameraCoordinator(hass, entry.entry_id, dict(entry.data))
    coordinator.async_start_refresh_loop()
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        coordinator: HueCameraCoordinator = hass.data[DOMAIN].pop(entry.entry_id)
        coordinator.async_stop()
    return unloaded
