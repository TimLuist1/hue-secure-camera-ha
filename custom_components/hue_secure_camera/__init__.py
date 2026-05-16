"""Philips Hue Secure Camera — HA integration entry point."""
from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .coordinator import HueCameraCoordinator

_LOGGER = logging.getLogger(__name__)

PLATFORMS = ["camera"]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up integration from a config entry."""
    hass.data.setdefault(DOMAIN, {})

    coordinator = HueCameraCoordinator(hass, entry.data)
    hass.data[DOMAIN][entry.entry_id] = coordinator

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Listen for option updates (new token / passphrase)
    entry.async_on_unload(entry.add_update_listener(_async_update_listener))

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    coordinator: HueCameraCoordinator = hass.data[DOMAIN].pop(entry.entry_id, None)
    if coordinator:
        await coordinator.stop_stream()

    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)


async def _async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Handle options update (reload to apply new token / passphrase)."""
    await hass.config_entries.async_reload(entry.entry_id)
