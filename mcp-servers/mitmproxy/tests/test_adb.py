# ABOUTME: Tests for Android adb proxy control
# ABOUTME: Validates device listing and proxy enable/disable functionality

import pytest
from unittest.mock import patch, MagicMock
from mitmproxy_mcp.adb import (
    is_adb_available,
    list_devices,
    get_local_ip,
    enable_proxy,
    disable_proxy,
    get_current_proxy,
    DeviceInfo,
)


class TestAdbAvailability:
    def test_adb_available(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert is_adb_available() is True

    def test_adb_not_available(self):
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError()
            assert is_adb_available() is False


class TestListDevices:
    def test_list_devices_success(self):
        adb_output = """List of devices attached
17281JECB02222\tdevice usb:0-0 product:barbet model:Pixel_5a device:barbet transport_id:5
emulator-5554\tdevice
"""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=adb_output,
            )
            devices = list_devices()
            assert len(devices) == 2
            assert devices[0].id == "17281JECB02222"
            assert devices[0].model == "Pixel_5a"
            assert devices[1].id == "emulator-5554"

    def test_list_devices_none_connected(self):
        adb_output = """List of devices attached

"""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=adb_output,
            )
            devices = list_devices()
            assert len(devices) == 0

    def test_list_devices_adb_not_available(self):
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError()
            with pytest.raises(RuntimeError, match="adb not found"):
                list_devices()


class TestGetLocalIp:
    def test_get_local_ip_returns_valid_ip(self):
        ip = get_local_ip()
        assert ip is not None
        # Should be an IPv4 address format
        parts = ip.split(".")
        assert len(parts) == 4


class TestEnableProxy:
    def test_enable_proxy_success(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            result = enable_proxy("192.168.1.100", 8080, device_id="17281JECB02222")
            assert result is True
            mock_run.assert_called_once()
            call_args = mock_run.call_args[0][0]
            assert "adb" in call_args
            assert "-s" in call_args
            assert "17281JECB02222" in call_args
            assert "settings" in call_args
            assert "put" in call_args
            assert "global" in call_args
            assert "http_proxy" in call_args
            assert "192.168.1.100:8080" in call_args

    def test_enable_proxy_no_device_id(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            result = enable_proxy("192.168.1.100", 8080)
            assert result is True
            call_args = mock_run.call_args[0][0]
            # Should not have -s flag when no device_id
            assert "-s" not in call_args

    def test_enable_proxy_failure(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stdout="", stderr="error: device not found"
            )
            result = enable_proxy("192.168.1.100", 8080)
            assert result is False


class TestDisableProxy:
    def test_disable_proxy_success(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            result = disable_proxy(device_id="17281JECB02222")
            assert result is True
            call_args = mock_run.call_args[0][0]
            assert "adb" in call_args
            assert ":0" in call_args

    def test_disable_proxy_no_device_id(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            result = disable_proxy()
            assert result is True


class TestGetCurrentProxy:
    def test_get_current_proxy_set(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="192.168.1.100:8080\n", stderr=""
            )
            proxy = get_current_proxy(device_id="17281JECB02222")
            assert proxy == "192.168.1.100:8080"

    def test_get_current_proxy_not_set(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="null\n", stderr="")
            proxy = get_current_proxy()
            assert proxy is None

    def test_get_current_proxy_colon_zero(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=":0\n", stderr="")
            proxy = get_current_proxy()
            assert proxy is None
