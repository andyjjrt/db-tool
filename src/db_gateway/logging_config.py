"""Uvicorn access-log redaction for authentication query strings.

``/auth/callback`` carries a one-time authorization code and ``/auth/login``
carries state, nonce and the PKCE challenge. Uvicorn's access logger writes
the full request path including the query string, so
:func:`install_access_log_filter` attaches a filter to ``uvicorn.access`` that
strips the query string from ``/auth/`` lines before any formatter sees them.
``create_app`` installs it, so the documented ``uvicorn
db_gateway.app:create_app --factory`` command is safe without extra flags.
Programmatic launchers can pass :data:`UVICORN_LOG_CONFIG` to ``uvicorn.run``.
A reverse proxy in front of the gateway must redact the same query strings.
"""

from __future__ import annotations

import logging
from typing import Any

REDACTED_PREFIX = "/auth/"


def redact_query_string(path: str) -> str:
    """Return the path without its query string when it is an ``/auth/`` path."""
    bare, separator, _query = path.partition("?")
    if separator and bare.startswith(REDACTED_PREFIX):
        return bare
    return path


class AuthQueryRedactionFilter(logging.Filter):
    """Strip query strings from ``/auth/`` access-log records.

    Uvicorn's access logger emits a five-tuple ``(client_addr, method,
    full_path, http_version, status_code)``; dict-style arguments are handled
    too so the filter keeps working if uvicorn changes the shape.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and len(args) >= 3 and isinstance(args[2], str):
            record.args = (*args[:2], redact_query_string(args[2]), *args[3:])
        elif isinstance(args, dict):
            for key in ("full_path", "path", "request_line"):
                value = args.get(key)
                if isinstance(value, str):
                    args[key] = redact_query_string(value)
        return True


def install_access_log_filter() -> AuthQueryRedactionFilter:
    """Attach the filter to ``uvicorn.access`` once; safe to call repeatedly."""
    logger = logging.getLogger("uvicorn.access")
    for existing in logger.filters:
        if isinstance(existing, AuthQueryRedactionFilter):
            return existing
    filter_ = AuthQueryRedactionFilter()
    logger.addFilter(filter_)
    return filter_


# For programmatic launchers: uvicorn.run(app, log_config=UVICORN_LOG_CONFIG).
UVICORN_LOG_CONFIG: dict[str, Any] = {
    "version": 1,
    "disable_existing_loggers": False,
    "filters": {
        "redact_auth_query": {"()": "db_gateway.logging_config.AuthQueryRedactionFilter"}
    },
    "formatters": {
        "default": {
            "()": "uvicorn.logging.DefaultFormatter",
            "fmt": "%(levelprefix)s %(message)s",
        },
        "access": {
            "()": "uvicorn.logging.AccessFormatter",
            "fmt": '%(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s',
        },
    },
    "handlers": {
        "default": {
            "formatter": "default",
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stderr",
        },
        "access": {
            "formatter": "access",
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stdout",
            "filters": ["redact_auth_query"],
        },
    },
    "loggers": {
        "uvicorn": {"handlers": ["default"], "level": "INFO", "propagate": False},
        "uvicorn.error": {"level": "INFO"},
        "uvicorn.access": {"handlers": ["access"], "level": "INFO", "propagate": False},
    },
}
