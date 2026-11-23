import logging
import struct
import time

import requests

from opencanary.logger import SlackHandler, TeamsHandler, WebhookHandler
from opencanary.modules.mssql import MSSQLProtocol
from opencanary.modules.ssh import CanarySSH


class FakeConfig:
    def __init__(self, settings):
        self.settings = settings

    def getVal(self, key, default=None):
        return self.settings.get(key, default)


def test_ssh_preauth_banner_gets_trailing_crlf():
    ssh = CanarySSH(config=FakeConfig({"ssh.preauth_banner": "Authorized only"}))
    assert ssh.preauth_banner == b"Authorized only\r\n"


def _record(msg='{"logtype": 4002, "logdata": {"PASSWORD": "Hunter2!"}}'):
    return logging.LogRecord("t", logging.WARNING, __file__, 1, msg, None, None)


def _handlers():
    return (
        WebhookHandler("http://127.0.0.1:9/hook"),
        SlackHandler("http://127.0.0.1:9/slack"),
        TeamsHandler("http://127.0.0.1:9/teams"),
    )


def _wait(handler):
    deadline = time.time() + 5
    while handler._queue.unfinished_tasks and time.time() < deadline:
        time.sleep(0.01)


def test_http_handlers_fail_quietly_with_a_timeout(monkeypatch, capsys):
    seen = []

    def refuse(*args, **kwargs):
        seen.append(kwargs.get("timeout"))
        raise requests.ConnectionError("refused")

    monkeypatch.setattr(requests, "request", refuse)
    monkeypatch.setattr(requests, "post", refuse)
    for handler in _handlers():
        handler.emit(_record())
    time.sleep(0.5)
    assert seen and all(seen)  # every delivery attempt set a timeout
    err = capsys.readouterr().err
    assert "delivery failed: ConnectionError" in err
    assert "Hunter2!" not in err  # the record body is never echoed


def test_slow_endpoint_does_not_block_the_caller(monkeypatch):
    monkeypatch.setattr(requests, "request", lambda *a, **k: time.sleep(2))
    handler = WebhookHandler("http://127.0.0.1:9/hook")
    start = time.time()
    for _ in range(5):
        handler.emit(_record())
    assert time.time() - start < 0.5


def test_mssql_login7_password_is_decoded():
    def field(text):
        return text.encode("utf-16-le")

    def obfuscate(raw):
        return bytes(((((b << 4) & 0xF0) | (b >> 4)) ^ 0xA5) for b in raw)

    host, user, pw = field("WS01"), field("sa_report"), obfuscate(field("S3cret!pw"))
    hfmt = "< 6I 4B l I 18H 6s 6H I"
    hlen = struct.calcsize(hfmt)
    values = [0] * len(MSSQLProtocol.LOGIN7_FIELDS)
    values[MSSQLProtocol.LOGIN7_FIELDS.index("ClientID")] = b"\0" * 6
    offset = hlen
    payload = b""
    for name, data in (("HostName", host), ("UserName", user), ("Password", pw)):
        values[MSSQLProtocol.LOGIN7_FIELDS.index("ib" + name)] = offset
        values[MSSQLProtocol.LOGIN7_FIELDS.index("cch" + name)] = len(data) // 2
        payload += data
        offset += len(data)
    packet = struct.pack(hfmt, *values) + payload
    login = MSSQLProtocol.parseLogin7(packet)
    assert login["UserName"] == "sa_report"
    assert login["Password"] == "S3cret!pw"
