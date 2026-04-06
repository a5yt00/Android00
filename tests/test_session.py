import pytest
from unittest.mock import patch, MagicMock
import subprocess

from androidaudit.session import ADBSession
from androidaudit.exceptions import DeviceNotFoundError, RootNotAvailableError

@patch("androidaudit.session.AdbClient")
def test_adb_session_connect(mock_client_class):
    # Setup mock Client and Device
    mock_client = MagicMock()
    mock_client_class.return_value = mock_client
    
    mock_device = MagicMock()
    mock_device.serial = "mock-device-123"
    
    # Simulate root check and frida check via shell()
    mock_device.shell.side_effect = lambda cmd: "uid=0(root)" if cmd == "id" else "frida-server"
    mock_client.devices.return_value = [mock_device]
    
    with patch("subprocess.run"):
        session = ADBSession()
        session.connect()
        assert session.device is not None
        assert session.serial == "mock-device-123"

@patch("androidaudit.session.AdbClient")
def test_adb_session_no_device(mock_client_class):
    mock_client = MagicMock()
    mock_client_class.return_value = mock_client
    mock_client.devices.return_value = []
    
    with patch("subprocess.run"):
        session = ADBSession()
        with pytest.raises(DeviceNotFoundError):
            session.connect()

@patch("androidaudit.session.AdbClient")
def test_adb_session_not_rooted(mock_client_class):
    mock_client = MagicMock()
    mock_client_class.return_value = mock_client
    
    mock_device = MagicMock()
    mock_device.serial = "mock-device-123"
    
    # Return a normal user uid for `id`
    mock_device.shell.side_effect = lambda cmd: "uid=2000(shell)" if cmd == "id" else ""
    mock_client.devices.return_value = [mock_device]
    
    with patch("subprocess.run", return_value=MagicMock(stdout=b"", stderr=b"")):
        session = ADBSession()
        with pytest.raises(RootNotAvailableError):
            session.connect()
