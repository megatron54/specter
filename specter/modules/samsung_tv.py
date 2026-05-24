"""Samsung Smart TV control module.

Samsung TVs (2016+) expose a WebSocket API on ports 8001 (HTTP) and 8002 (HTTPS)
that allows unauthenticated remote control. On first connection, the TV shows a
prompt to allow/deny — but many TVs have this auto-accepted or previously accepted.

Capabilities (NO authentication required once paired):
- Power off
- Send remote control keys (volume, channel, menu navigation)
- Launch apps
- Get device info
- Send text input
"""

import json
import base64
import ssl
from dataclasses import dataclass

import httpx


@dataclass
class SamsungTV:
    """Represents a Samsung Smart TV."""

    ip: str
    port: int = 8002  # HTTPS WebSocket (8001 for plain HTTP)
    name: str = "Unknown"
    model: str = "Unknown"
    app_name: str = "Specter"  # Shows on TV as the controlling app

    @property
    def base_url(self) -> str:
        scheme = "https" if self.port == 8002 else "http"
        return f"{scheme}://{self.ip}:{self.port}"

    @property
    def ws_url(self) -> str:
        scheme = "wss" if self.port == 8002 else "ws"
        encoded_name = base64.b64encode(self.app_name.encode()).decode()
        return f"{scheme}://{self.ip}:{self.port}/api/v2/channels/samsung.remote.control?name={encoded_name}"


# Samsung TV remote control key codes
class Keys:
    POWER_OFF = "KEY_POWER"
    POWER_TOGGLE = "KEY_POWEROFF"
    VOLUME_UP = "KEY_VOLUP"
    VOLUME_DOWN = "KEY_VOLDOWN"
    MUTE = "KEY_MUTE"
    CHANNEL_UP = "KEY_CHUP"
    CHANNEL_DOWN = "KEY_CHDOWN"
    MENU = "KEY_MENU"
    HOME = "KEY_HOME"
    BACK = "KEY_RETURN"
    ENTER = "KEY_ENTER"
    UP = "KEY_UP"
    DOWN = "KEY_DOWN"
    LEFT = "KEY_LEFT"
    RIGHT = "KEY_RIGHT"
    SOURCE = "KEY_SOURCE"
    HDMI = "KEY_HDMI"
    PLAY = "KEY_PLAY"
    PAUSE = "KEY_PAUSE"
    STOP = "KEY_STOP"


class SamsungTVModule:
    """Control interface for Samsung Smart TVs.

    Uses the REST API for device info and the WebSocket API for remote control.
    """

    def __init__(self, tv: SamsungTV):
        self.tv = tv
        self._client = httpx.Client(verify=False, timeout=5.0)
        self._ws = None

    def get_device_info(self) -> dict | None:
        """Fetch TV device info via REST API. NO AUTH REQUIRED.

        Returns device name, model, ID, network info, and available apps.
        """
        try:
            resp = self._client.get(f"{self.tv.base_url}/api/v2/")
            if resp.status_code == 200:
                data = resp.json()
                if "device" in data:
                    self.tv.name = data["device"].get("name", "Unknown")
                    self.tv.model = data["device"].get("modelName", "Unknown")
                return data
        except (httpx.ConnectError, httpx.ReadTimeout):
            pass
        return None

    def get_installed_apps(self) -> list[dict] | None:
        """Get list of installed apps. NO AUTH REQUIRED on some models."""
        try:
            resp = self._client.get(f"{self.tv.base_url}/api/v2/applications")
            if resp.status_code == 200:
                return resp.json()
        except (httpx.ConnectError, httpx.ReadTimeout):
            pass
        return None

    def is_available(self) -> bool:
        """Check if the TV is on and reachable."""
        info = self.get_device_info()
        return info is not None

    def send_key(self, key: str) -> bool:
        """Send a remote control key press via WebSocket.

        Note: This requires the websockets library for full implementation.
        For now, this uses the REST endpoint available on some models.

        Args:
            key: Key code (use Keys class constants).

        Returns:
            True if command was sent successfully.
        """
        # Some Samsung TVs accept key commands via REST on older firmware
        try:
            payload = {
                "method": "ms.remote.control",
                "params": {
                    "Cmd": "Click",
                    "DataOfCmd": key,
                    "Option": "false",
                    "TypeOfRemote": "SendRemoteKey",
                },
            }
            resp = self._client.post(
                f"{self.tv.base_url}/api/v2/channels/samsung.remote.control",
                json=payload,
            )
            return resp.status_code == 200
        except (httpx.ConnectError, httpx.ReadTimeout):
            return False

    def power_off(self) -> bool:
        """Turn off the TV."""
        return self.send_key(Keys.POWER_OFF)

    def volume_up(self, times: int = 1) -> None:
        """Increase volume."""
        for _ in range(times):
            self.send_key(Keys.VOLUME_UP)

    def volume_down(self, times: int = 1) -> None:
        """Decrease volume."""
        for _ in range(times):
            self.send_key(Keys.VOLUME_DOWN)

    def mute(self) -> bool:
        """Toggle mute."""
        return self.send_key(Keys.MUTE)

    def launch_app(self, app_id: str) -> bool:
        """Launch an app by its ID.

        Args:
            app_id: Application ID (get from get_installed_apps).
        """
        try:
            resp = self._client.post(
                f"{self.tv.base_url}/api/v2/applications/{app_id}",
                json={"id": app_id},
            )
            return resp.status_code == 200
        except (httpx.ConnectError, httpx.ReadTimeout):
            return False
