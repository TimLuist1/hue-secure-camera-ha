"""Camera entity for a Hue Secure camera (frames pushed by the browser viewer)."""
from __future__ import annotations

import logging
from typing import Optional

from homeassistant.components.camera import Camera, CameraEntityFeature
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import CONF_DEVICE_MAC, CONF_DEVICE_NAME, CONF_HOME_ID, DOMAIN
from .coordinator import HueCameraCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    coordinator: HueCameraCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([HueSecureCamera(coordinator, entry)])


class HueSecureCamera(Camera):
    """Snapshot camera backed by the live browser stream."""

    _attr_has_entity_name = True
    _attr_name = None
    _attr_supported_features = CameraEntityFeature(0)

    def __init__(self, coordinator: HueCameraCoordinator, entry: ConfigEntry) -> None:
        super().__init__()
        self._coordinator = coordinator
        self._attr_unique_id = f"{entry.data[CONF_HOME_ID]}_{entry.data[CONF_DEVICE_MAC]}"
        self._entry_id = entry.entry_id
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.data[CONF_DEVICE_MAC])},
            name=entry.data.get(CONF_DEVICE_NAME, entry.data[CONF_DEVICE_MAC]),
            manufacturer="Philips / Signify",
            model="Hue Secure Camera",
        )

    async def async_camera_image(
        self, width: Optional[int] = None, height: Optional[int] = None
    ) -> Optional[bytes]:
        return self._coordinator.latest_frame

    @property
    def extra_state_attributes(self) -> dict:
        return {"entry_id": self._entry_id}

    @property
    def is_streaming(self) -> bool:
        return self._coordinator.is_streaming

    @property
    def brand(self) -> str:
        return "Philips Hue"

    @property
    def frame_interval(self) -> float:
        return 0.1
