import pytest
from pathlib import Path
from unittest.mock import MagicMock
from androidaudit.session import ADBSession

@pytest.fixture
def mock_adb_session() -> MagicMock:
    """Fixture providing a mocked ADBSession for tests."""
    session = MagicMock(spec=ADBSession)
    session.shell.return_value = "mock_output"
    return session

@pytest.fixture
def sample_apk_path() -> Path:
    """Fixture providing the path to the sample test APK."""
    return Path(__file__).parent / "fixtures" / "sample.apk"
