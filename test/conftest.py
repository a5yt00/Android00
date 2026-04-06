import pytest
from unittest.mock import MagicMock
from pathlib import Path

@pytest.fixture
def mock_adb_session():
    """Returns a mocked ADBSession to test modules without a device."""
    session = MagicMock()
    session.shell.return_value = "success"
    session.pull.return_value = True
    return session

@pytest.fixture
def sample_apk_path():
    return Path("tests/fixtures/sample.apk")