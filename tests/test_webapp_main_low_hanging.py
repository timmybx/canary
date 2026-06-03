from __future__ import annotations

from typing import Any

import pytest

import canary.webapp as webapp


def test_main_uses_waitress_with_env_values(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    captured: dict[str, Any] = {}

    def fake_waitress_serve(app: object, **kwargs: Any) -> None:
        captured["app"] = app
        captured.update(kwargs)

    monkeypatch.setattr(webapp, "waitress_serve", fake_waitress_serve)
    monkeypatch.setenv("CANARY_WEB_HOST", "0.0.0.0")
    monkeypatch.setenv("PORT", "9000")
    monkeypatch.setenv("CANARY_WEB_THREADS", "12")
    monkeypatch.setenv("CANARY_WEB_CONNECTION_LIMIT", "345")

    webapp.main()

    assert captured == {
        "app": webapp.app,
        "host": "0.0.0.0",
        "port": 9000,
        "threads": 12,
        "connection_limit": 345,
    }
    output = capsys.readouterr().out
    assert "CANARY web console running on http://0.0.0.0:9000" in output
    assert "Using waitress with threads=12 and connection_limit=345" in output


def test_main_falls_back_to_defaults_for_invalid_numeric_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_waitress_serve(app: object, **kwargs: Any) -> None:
        captured["app"] = app
        captured.update(kwargs)

    monkeypatch.setattr(webapp, "waitress_serve", fake_waitress_serve)
    monkeypatch.setenv("CANARY_WEB_HOST", "127.0.0.2")
    monkeypatch.setenv("PORT", "not-a-port")
    monkeypatch.setenv("CANARY_WEB_THREADS", "not-threads")
    monkeypatch.setenv("CANARY_WEB_CONNECTION_LIMIT", "not-a-limit")

    webapp.main()

    assert captured == {
        "app": webapp.app,
        "host": "127.0.0.2",
        "port": 8000,
        "threads": 8,
        "connection_limit": 200,
    }


def test_main_uses_wsgiref_when_waitress_is_unavailable(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    captured: dict[str, Any] = {}

    class FakeServer:
        def __enter__(self) -> FakeServer:
            captured["entered"] = True
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            captured["exited"] = True

        def serve_forever(self) -> None:
            captured["served"] = True

    def fake_make_server(host: str, port: int, app: object) -> FakeServer:
        captured["host"] = host
        captured["port"] = port
        captured["app"] = app
        return FakeServer()

    monkeypatch.setattr(webapp, "waitress_serve", None)
    monkeypatch.setattr(webapp, "make_server", fake_make_server)
    monkeypatch.setenv("CANARY_WEB_HOST", "localhost")
    monkeypatch.setenv("CANARY_WEB_PORT", "7777")
    monkeypatch.delenv("PORT", raising=False)

    webapp.main()

    assert captured == {
        "host": "localhost",
        "port": 7777,
        "app": webapp.app,
        "entered": True,
        "served": True,
        "exited": True,
    }
    assert (
        "Waitress is not installed; falling back to wsgiref.simple_server"
        in capsys.readouterr().out
    )
