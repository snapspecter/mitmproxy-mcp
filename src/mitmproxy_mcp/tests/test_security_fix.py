import os
import pytest
from mitmproxy_mcp.core.server import MitmController


def test_get_verify_param_default_no_cert(monkeypatch):
    controller = MitmController()

    # Ensure the cert path doesn't exist
    monkeypatch.setattr(os.path, "exists", lambda x: False)

    # Should return True by default
    assert controller._get_verify_param() is True


def test_get_verify_param_override(monkeypatch):
    controller = MitmController()

    # Override with False
    assert controller._get_verify_param(verify_override=False) is False

    # Override with True
    assert controller._get_verify_param(verify_override=True) is True


def test_get_verify_param_with_cert(monkeypatch):
    controller = MitmController()

    # Mock cert existence
    cert_path = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")
    monkeypatch.setattr(os.path, "exists", lambda x: x == cert_path)

    # Should return the cert path
    assert controller._get_verify_param() == cert_path
