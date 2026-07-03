import os
import sys
import importlib
import pytest
import hashlib

def test_pbkdf2_derivation():
    """Verify PBKDF2 password derivation parameters and logic match server design."""
    password = "admin"
    salt = "default_salt_for_development"
    iterations = 100000
    derived = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), iterations)
    
    # Expected PBKDF2 hash of "admin" with "default_salt_for_development"
    expected_hex = "6c537790c2fc1990f71039615ca9f34a9862f73838ec342929da92984b07f436"
    assert derived.hex() == expected_hex

def test_server_config_defaults(monkeypatch):
    """Verify that server config loads standard fallbacks when env is empty."""
    # Ensure env variables are not present
    monkeypatch.delenv("STS_HOST", raising=False)
    monkeypatch.delenv("STS_PORT", raising=False)
    
    import server.config
    # Reload server.config to ensure env changes are reflected
    importlib.reload(server.config)
    
    assert server.config.HOST == "0.0.0.0"
    assert server.config.PORT == 6000
    assert "users.json" in server.config.USER_DB

def test_server_config_env_overrides(monkeypatch):
    """Verify that server config respects custom environment overrides."""
    monkeypatch.setenv("STS_HOST", "192.168.1.50")
    monkeypatch.setenv("STS_PORT", "9999")
    monkeypatch.setenv("DB_DIR", "custom_dir")
    
    import server.config
    importlib.reload(server.config)
    
    assert server.config.HOST == "192.168.1.50"
    assert server.config.PORT == 9999
    assert "custom_dir" in server.config.DB_DIR

def test_client_config_defaults(monkeypatch):
    """Verify that client config loads standard fallbacks when env is empty."""
    monkeypatch.delenv("KDC_IP", raising=False)
    monkeypatch.delenv("KDC_PORT", raising=False)
    
    import client.config
    importlib.reload(client.config)
    
    assert client.config.KDC_IP == "127.0.0.1"
    assert client.config.KDC_PORT == 6000

def test_client_config_env_overrides(monkeypatch):
    """Verify that client config respects custom environment overrides."""
    monkeypatch.setenv("KDC_IP", "10.0.0.1")
    monkeypatch.setenv("KDC_PORT", "12345")
    
    import client.config
    importlib.reload(client.config)
    
    assert client.config.KDC_IP == "10.0.0.1"
    assert client.config.KDC_PORT == 12345
