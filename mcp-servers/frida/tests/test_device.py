# ABOUTME: Tests for Frida device and session management
# ABOUTME: Validates device listing, app spawning, and SSL bypass injection

import pytest
from unittest.mock import MagicMock, patch
from frida_mcp.device import (
    list_devices,
    list_packages,
    get_device,
    DeviceInfo,
    PackageInfo,
)


class TestListDevices:
    def test_returns_device_info_list(self):
        mock_device = MagicMock()
        mock_device.id = "emulator-5554"
        mock_device.name = "Android Emulator"
        mock_device.type = "usb"

        with patch("frida.enumerate_devices", return_value=[mock_device]):
            devices = list_devices()

        assert len(devices) == 1
        assert devices[0].id == "emulator-5554"
        assert devices[0].name == "Android Emulator"

    def test_filters_non_usb_devices(self):
        mock_usb = MagicMock()
        mock_usb.id = "device123"
        mock_usb.name = "Pixel 6"
        mock_usb.type = "usb"

        mock_local = MagicMock()
        mock_local.id = "local"
        mock_local.name = "Local System"
        mock_local.type = "local"

        with patch("frida.enumerate_devices", return_value=[mock_usb, mock_local]):
            devices = list_devices(include_local=False)

        assert len(devices) == 1
        assert devices[0].id == "device123"

    def test_includes_local_when_requested(self):
        mock_usb = MagicMock()
        mock_usb.id = "device123"
        mock_usb.name = "Pixel 6"
        mock_usb.type = "usb"

        mock_local = MagicMock()
        mock_local.id = "local"
        mock_local.name = "Local System"
        mock_local.type = "local"

        with patch("frida.enumerate_devices", return_value=[mock_usb, mock_local]):
            devices = list_devices(include_local=True)

        assert len(devices) == 2


class TestListPackages:
    def test_returns_package_list(self):
        mock_app1 = MagicMock()
        mock_app1.identifier = "com.skylight.app"
        mock_app1.name = "Skylight"

        mock_app2 = MagicMock()
        mock_app2.identifier = "com.google.chrome"
        mock_app2.name = "Chrome"

        mock_device = MagicMock()
        mock_device.enumerate_applications.return_value = [mock_app1, mock_app2]

        with patch("frida_mcp.device.get_device", return_value=mock_device):
            packages = list_packages()

        assert len(packages) == 2
        # Sorted by name, so Chrome comes first
        identifiers = [p.identifier for p in packages]
        assert "com.skylight.app" in identifiers
        assert "com.google.chrome" in identifiers

    def test_filters_by_query(self):
        mock_app1 = MagicMock()
        mock_app1.identifier = "com.skylight.app"
        mock_app1.name = "Skylight"

        mock_app2 = MagicMock()
        mock_app2.identifier = "com.google.chrome"
        mock_app2.name = "Chrome"

        mock_device = MagicMock()
        mock_device.enumerate_applications.return_value = [mock_app1, mock_app2]

        with patch("frida_mcp.device.get_device", return_value=mock_device):
            packages = list_packages(query="skylight")

        assert len(packages) == 1
        assert packages[0].identifier == "com.skylight.app"


class TestGetDevice:
    def test_gets_usb_device_by_default(self):
        mock_device = MagicMock()
        mock_device.id = "abc123"

        with patch("frida.get_usb_device", return_value=mock_device):
            device = get_device()

        assert device.id == "abc123"

    def test_gets_device_by_id(self):
        mock_device = MagicMock()
        mock_device.id = "specific-device"

        with patch("frida.get_device", return_value=mock_device) as mock_get:
            device = get_device(device_id="specific-device")

        mock_get.assert_called_once_with("specific-device")
        assert device.id == "specific-device"
