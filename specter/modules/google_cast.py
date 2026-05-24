"""Google Cast local API module.

Interacts with Google Home/Nest devices via their unauthenticated (or
token-authenticated) local HTTPS API on port 8443.

Capabilities:
- Device info enumeration (name, MAC, WiFi, capabilities)
- Reboot / factory reset
- Do Not Disturb toggle
- Alarm/timer enumeration and deletion
- Saved WiFi network enumeration
- Nearby Bluetooth device scanning
- Night mode manipulation
"""

from dataclasses import dataclass
import httpx


CAST_PORT = 8443
BASE_PATH = "/setup"


@dataclass
class CastDevice:
    """Represents a Google Cast device."""

    ip: str
    name: str = "Unknown"
    model: str = "Unknown"
    mac: str = ""
    build_version: str = ""
    local_auth_token: str = ""

    @property
    def base_url(self) -> str:
        return f"https://{self.ip}:{CAST_PORT}{BASE_PATH}"


class GoogleCastModule:
    """Control interface for Google Cast devices."""

    def __init__(self, device: CastDevice):
        self.device = device
        self._client = httpx.Client(
            verify=False,  # Self-signed cert on the device
            timeout=10.0,
            headers=self._build_headers(),
        )

    def _build_headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.device.local_auth_token:
            headers["cast-local-authorization-token"] = self.device.local_auth_token
        return headers

    def get_device_info(self) -> dict:
        """Fetch full device information via /eureka_info.

        Returns device name, build info, network config, WiFi details,
        capabilities, and more.
        """
        params = {
            "params": "version,audio,name,build_info,detail,device_info,net,wifi,setup,settings,opt_in,opencast,multizone,proxy,night_mode_params,user_eq,room_equalizer",
            "options": "detail",
            "nonce": "12345",
        }
        resp = self._client.get(f"{self.device.base_url}/eureka_info", params=params)
        resp.raise_for_status()
        return resp.json()

    def reboot(self) -> bool:
        """Reboot the device.

        Returns:
            True if command was accepted.
        """
        resp = self._client.post(
            f"{self.device.base_url}/reboot",
            json={"params": "now"},
        )
        return resp.status_code == 200

    def factory_reset(self) -> bool:
        """Factory reset the device. USE WITH CAUTION.

        Returns:
            True if command was accepted.
        """
        resp = self._client.post(
            f"{self.device.base_url}/reboot",
            json={"params": "fdr"},
        )
        return resp.status_code == 200

    def set_do_not_disturb(self, enabled: bool) -> dict:
        """Toggle Do Not Disturb mode.

        Args:
            enabled: True to enable DND, False to disable.

        Returns:
            Current notification state.
        """
        resp = self._client.post(
            f"{self.device.base_url}/assistant/notifications",
            json={"notifications_enabled": not enabled},
        )
        resp.raise_for_status()
        return resp.json()

    def get_alarms(self) -> dict:
        """Get all active alarms and timers."""
        resp = self._client.get(f"{self.device.base_url}/assistant/alarms")
        resp.raise_for_status()
        return resp.json()

    def delete_alarms(self, ids: list[str]) -> bool:
        """Delete alarms/timers by their IDs.

        Args:
            ids: List of alarm/timer IDs (e.g., ['alarm/xxx', 'timer/yyy']).
        """
        resp = self._client.post(
            f"{self.device.base_url}/assistant/alarms/delete",
            json={"ids": ids},
        )
        return resp.status_code == 200

    def get_saved_wifi_networks(self) -> list[dict]:
        """Get all saved WiFi networks on the device."""
        resp = self._client.get(f"{self.device.base_url}/configured_networks")
        resp.raise_for_status()
        return resp.json()

    def forget_wifi(self, wpa_id: int) -> bool:
        """Forget a saved WiFi network, potentially disconnecting the device.

        Args:
            wpa_id: The WiFi network ID from get_saved_wifi_networks().
        """
        resp = self._client.post(
            f"{self.device.base_url}/forget_wifi",
            json={"wpa_id": wpa_id},
        )
        return resp.status_code == 200

    def scan_bluetooth(self, timeout: int = 30) -> list[dict]:
        """Initiate Bluetooth scan and return results.

        Args:
            timeout: Scan duration in seconds.
        """
        # Start scan
        self._client.post(
            f"{self.device.base_url}/bluetooth/scan",
            json={"enable": True, "clear_results": True, "timeout": timeout},
        )
        # Wait and fetch results
        import time
        time.sleep(min(timeout, 10))

        resp = self._client.get(f"{self.device.base_url}/bluetooth/scan_results")
        resp.raise_for_status()
        return resp.json()

    def scan_wifi(self) -> list[dict]:
        """Scan for nearby WiFi networks visible to the device."""
        self._client.post(f"{self.device.base_url}/scan_wifi")
        import time
        time.sleep(3)
        resp = self._client.get(f"{self.device.base_url}/scan_results")
        resp.raise_for_status()
        return resp.json()

    def set_night_mode(self, enabled: bool, volume: float = 0.5, led_brightness: float = 0.5) -> dict:
        """Configure night mode settings.

        Args:
            enabled: Enable or disable night mode.
            volume: Max volume during night mode (0.0 - 1.0).
            led_brightness: Max LED brightness during night mode (0.0 - 1.0).
        """
        resp = self._client.post(
            f"{self.device.base_url}/assistant/set_night_mode_params",
            json={
                "enabled": enabled,
                "do_not_disturb": enabled,
                "led_brightness": led_brightness,
                "volume": volume,
                "demo_to_user": True,
                "windows": [{"length_hours": 24, "days": [0, 1, 2, 3, 4, 5, 6], "start_hour": 0}],
            },
        )
        resp.raise_for_status()
        return resp.json()
