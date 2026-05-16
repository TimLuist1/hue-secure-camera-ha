"""Camera entity for Hue Secure Camera."""
from __future__ import annotations

import asyncio
import io
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
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the camera entity from a config entry."""
    coordinator: HueCameraCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([HueSecureCamera(coordinator, entry)], True)


class HueSecureCamera(Camera):
    """Philips Hue Secure Camera entity.

    Provides:
      - async_camera_image()  → JPEG snapshot (for HA frontend / notifications)
      - stream_source()       → None (stream delivered via on_frame callback + internal queue)
    """

    _attr_has_entity_name = True
    _attr_name = None  # use device name
    _attr_supported_features = CameraEntityFeature(0)

    def __init__(
        self,
        coordinator: HueCameraCoordinator,
        entry: ConfigEntry,
    ) -> None:
        super().__init__()
        self._coordinator = coordinator
        self._entry = entry
        self._mac = entry.data[CONF_DEVICE_MAC]
        self._cam_name = entry.data.get(CONF_DEVICE_NAME, f"Hue Camera {self._mac}")
        self._home_id = entry.data[CONF_HOME_ID]

        self._attr_unique_id = f"{self._home_id}_{self._mac}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, self._mac)},
            name=self._cam_name,
            manufacturer="Philips / Signify",
            model="Hue Secure Floodlight Camera (CMW002)",
        )
        self._attr_is_streaming = False
        self._start_task: Optional[asyncio.Task] = None

    # ── Lifecycle ─────────────────────────────────────────────────────────

    async def async_added_to_hass(self) -> None:
        """Start stream when entity is added."""
        await super().async_added_to_hass()
        self._start_task = self.hass.async_create_task(self._start_stream())

    async def async_will_remove_from_hass(self) -> None:
        """Stop stream when entity is removed."""
        if self._start_task:
            self._start_task.cancel()
        await self._coordinator.stop_stream()
        await super().async_will_remove_from_hass()

    async def _start_stream(self) -> None:
        connected = await self._coordinator.start_stream()
        self._attr_is_streaming = connected
        self.async_write_ha_state()

    # ── Camera interface ──────────────────────────────────────────────────

    async def async_camera_image(
        self,
        width: Optional[int] = None,
        height: Optional[int] = None,
    ) -> Optional[bytes]:
        """Return a JPEG snapshot."""
        if not self._coordinator.is_streaming:
            # Attempt to start/restart the stream
            self.hass.async_create_task(self._start_stream())
            return None

        frame = await self._coordinator.get_latest_frame()
        if frame is None:
            return None

        # If we need to resize, do it here with PIL (optional)
        jpeg = frame.jpeg
        if (width or height) and jpeg:
            try:
                from PIL import Image  # type: ignore[import]

                img = Image.open(io.BytesIO(jpeg))
                w, h = img.size
                if width and height:
                    img = img.resize((width, height), Image.LANCZOS)
                elif width:
                    ratio = width / w
                    img = img.resize((width, int(h * ratio)), Image.LANCZOS)
                elif height:
                    ratio = height / h
                    img = img.resize((int(w * ratio), height), Image.LANCZOS)
                buf = io.BytesIO()
                img.save(buf, format="JPEG", quality=85)
                return buf.getvalue()
            except ImportError:
                pass  # PIL not available, return original

        return jpeg

    @property
    def is_recording(self) -> bool:
        return False

    @property
    def brand(self) -> str:
        return "Philips Hue"

    @property
    def model(self) -> str:
        return "CMW002"

    @property
    def frame_interval(self) -> float:
        return 1 / 15  # 15 fps
