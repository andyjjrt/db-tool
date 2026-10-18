"""Access-log redaction for OIDC codes, state and nonce query strings."""

from __future__ import annotations

import io
import json
import logging
from pathlib import Path

import pytest
import uvicorn.logging

from db_gateway.logging_config import (
    UVICORN_LOG_CONFIG,
    AuthQueryRedactionFilter,
    install_access_log_filter,
    redact_query_string,
)

FORMAT = '%(client_addr)s - "%(request_line)s" %(status_code)s'


def access_record(path: str) -> logging.LogRecord:
    """A record shaped exactly like uvicorn's access logger emission."""
    return logging.LogRecord(
        name="uvicorn.access",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg='%s - "%s %s HTTP/%s" %d',
        args=("127.0.0.1:1234", "GET", path, "1.1", 400),
        exc_info=None,
    )


@pytest.mark.parametrize(
    "path, expected",
    [
        ("/auth/callback?code=abc&state=def", "/auth/callback"),
        ("/auth/login?next=/dashboard", "/auth/login"),
        ("/auth/callback", "/auth/callback"),
        ("/api/me?verbose=1", "/api/me?verbose=1"),
        ("/healthz", "/healthz"),
    ],
)
def test_redact_query_string(path: str, expected: str) -> None:
    assert redact_query_string(path) == expected


def test_filter_redacts_a_real_uvicorn_access_record() -> None:
    record = access_record(
        "/auth/callback?code=CODE_SENTINEL&state=STATE_SENTINEL&nonce=NONCE_SENTINEL"
    )
    assert AuthQueryRedactionFilter().filter(record)
    formatted = uvicorn.logging.AccessFormatter(FORMAT).format(record)
    assert "CODE_SENTINEL" not in formatted
    assert "STATE_SENTINEL" not in formatted
    assert "NONCE_SENTINEL" not in formatted
    assert "/auth/callback" in formatted
    assert "400" in formatted


def test_filter_leaves_non_auth_query_strings_alone() -> None:
    record = access_record("/api/me?verbose=1")
    assert AuthQueryRedactionFilter().filter(record)
    formatted = uvicorn.logging.AccessFormatter(FORMAT).format(record)
    assert "/api/me?verbose=1" in formatted


def test_installed_filter_redacts_real_logger_output() -> None:
    logger = logging.getLogger("uvicorn.access")
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(uvicorn.logging.AccessFormatter(FORMAT))
    previous_level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        install_access_log_filter()
        logger.info(
            '%s - "%s %s HTTP/%s" %d',
            "127.0.0.1:9999",
            "GET",
            "/auth/callback?code=CODE_SENTINEL&state=STATE_SENTINEL",
            "1.1",
            503,
        )
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)
    output = stream.getvalue()
    assert "CODE_SENTINEL" not in output
    assert "STATE_SENTINEL" not in output
    assert "/auth/callback" in output and "503" in output


def test_install_is_idempotent() -> None:
    install_access_log_filter()
    install_access_log_filter()
    logger = logging.getLogger("uvicorn.access")
    assert sum(isinstance(item, AuthQueryRedactionFilter) for item in logger.filters) == 1


def test_uvicorn_log_config_declares_the_redaction_filter() -> None:
    access_handler = UVICORN_LOG_CONFIG["handlers"]["access"]
    assert access_handler["filters"] == ["redact_auth_query"]
    factory = UVICORN_LOG_CONFIG["filters"]["redact_auth_query"]["()"]
    assert factory == "db_gateway.logging_config.AuthQueryRedactionFilter"


def test_shipped_uvicorn_log_config_matches_the_python_config() -> None:
    path = Path(__file__).resolve().parents[2] / "src" / "db_gateway" / "logging_config.json"
    assert json.loads(path.read_text(encoding="utf-8")) == UVICORN_LOG_CONFIG
