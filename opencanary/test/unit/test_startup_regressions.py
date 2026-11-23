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


class Resp:
    def __init__(self, status):
        self.status_code = status
        self.text = ""


def _fast(handler):
    handler.RETRY_SECONDS = 0.5
    handler.BACKOFF_START = 0.02
    handler.BACKOFF_MAX = 0.05
    return handler


def _settle(handler, timeout=3):
    deadline = time.time() + timeout
    while handler._queue.unfinished_tasks and time.time() < deadline:
        time.sleep(0.01)


def test_retries_until_the_hub_recovers(monkeypatch):
    outcomes = iter([requests.ConnectionError("down"), Resp(503), Resp(204)])
    calls = []

    def fake(*args, **kwargs):
        calls.append(kwargs.get("timeout"))
        result = next(outcomes)
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(requests, "request", fake)
    handler = _fast(WebhookHandler("http://hub/v1/opencanary", status_code=204))
    handler.emit(_record())
    _settle(handler)
    assert handler.delivered == 1 and handler.exhausted == 0
    assert len(calls) == 3 and all(calls)  # every attempt has a timeout


def test_gives_up_quietly_and_counts(monkeypatch, capsys):
    monkeypatch.setattr(requests, "request", lambda *a, **k: Resp(503))
    monkeypatch.setattr(requests, "post", lambda *a, **k: Resp(503))
    for handler in (
        WebhookHandler("http://hub/hook", status_code=204),
        SlackHandler("http://s"),
        TeamsHandler("http://t"),
    ):
        _fast(handler).emit(_record())
        _settle(handler)
        assert handler.exhausted == 1 and handler.delivered == 0
    err = capsys.readouterr().err
    assert "gave up after retries (HTTP 503)" in err and "Hunter2!" not in err


def test_permanent_errors_are_not_retried(monkeypatch):
    calls = []
    monkeypatch.setattr(
        requests, "request", lambda *a, **k: calls.append(1) or Resp(401)
    )
    handler = _fast(WebhookHandler("http://hub/hook", status_code=204))
    handler.emit(_record())
    _settle(handler)
    assert len(calls) == 1


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
