import logging

import requests

from opencanary.logger import SlackHandler, TeamsHandler, WebhookHandler
from opencanary.modules.ssh import CanarySSH


class FakeConfig:
    def __init__(self, settings):
        self.settings = settings

    def getVal(self, key, default=None):
        return self.settings.get(key, default)


def test_ssh_preauth_banner_gets_trailing_crlf():
    ssh = CanarySSH(config=FakeConfig({"ssh.preauth_banner": "Authorized only"}))
    assert ssh.preauth_banner == b"Authorized only\r\n"


def _record(msg='{"logtype": 4002}'):
    return logging.LogRecord("t", logging.WARNING, __file__, 1, msg, None, None)


def test_http_handlers_survive_unreachable_endpoint(monkeypatch):
    def refuse(*args, **kwargs):
        assert kwargs.get("timeout"), "HTTP alert calls must set a timeout"
        raise requests.ConnectionError("refused")

    monkeypatch.setattr(requests, "request", refuse)
    monkeypatch.setattr(requests, "post", refuse)
    monkeypatch.setattr(logging, "raiseExceptions", False)

    for handler in (
        WebhookHandler("http://127.0.0.1:9/hook"),
        SlackHandler("http://127.0.0.1:9/slack"),
        TeamsHandler("http://127.0.0.1:9/teams"),
    ):
        handler.emit(_record())
