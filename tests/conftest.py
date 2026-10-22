from pathlib import Path
import pytest
from cryptography.fernet import Fernet
from vk_mcp.config import Settings
from vk_mcp.store import Store


@pytest.fixture
def settings(tmp_path):
    return Settings("https://example.test","https://example.test/auth/realms/vk",Fernet.generate_key().decode(),"x"*40,"dashboard","test-secret",tmp_path/"test.db")


@pytest.fixture
def store(settings):
    return Store(settings.db_path,settings.encryption_key)
