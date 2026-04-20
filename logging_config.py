"""
Structured JSON logging for InboxScore.

Every log line is emitted as a single JSON object on stdout (Render captures
stdout natively — no files, no rotation to manage). Each line carries the
current request_id (via a ContextVar set by RequestContextMiddleware), plus
any extra fields passed via ``logger.info("msg", extra={...})``.

Usage:
    from logging_config import setup_logging
    setup_logging(level="INFO")

    import logging
    logger = logging.getLogger(__name__)
    logger.info("scan.completed", extra={"domain": "example.com", "score": 66})

Outside a request, request_id defaults to "-" (e.g. scheduler jobs).
"""

from __future__ import annotations

import json
import logging
import sys
from contextvars import ContextVar
from datetime import datetime, timezone

# Set by RequestContextMiddleware per request; read by JSONFormatter on each log.
request_id_var: ContextVar[str] = ContextVar("request_id", default="-")


class JSONFormatter(logging.Formatter):
    """Render each LogRecord as a single-line JSON object.

    Always includes: ts (ISO-8601 UTC), level, logger, msg, request_id.
    Also includes any custom fields passed as ``extra={...}`` on the log call.
    """

    # Stdlib LogRecord fields we intentionally don't emit (noise / internal).
    _RESERVED = {
        "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
        "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
        "created", "msecs", "relativeCreated", "thread", "threadName",
        "processName", "process", "message", "taskName",
    }

    def format(self, record: logging.LogRecord) -> str:  # noqa: A003
        payload: dict = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "request_id": request_id_var.get(),
        }

        # Pick up anything passed as logger.xxx("msg", extra={"key": value})
        for k, v in record.__dict__.items():
            if k in self._RESERVED or k in payload:
                continue
            try:
                json.dumps(v)  # probe JSON-serialisability
                payload[k] = v
            except (TypeError, ValueError):
                payload[k] = str(v)

        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str, ensure_ascii=False)


def setup_logging(level: str = "INFO") -> None:
    """Configure root logger with a single JSON handler to stdout.

    Safe to call multiple times; previous handlers are removed first so
    uvicorn's pre-existing handlers don't double-emit.
    """
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    for h in list(root.handlers):
        root.removeHandler(h)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())
    root.addHandler(handler)

    # Quiet chatty third-party libs — they re-log at INFO what we don't need.
    for name in ("httpx", "httpcore", "urllib3", "apscheduler", "uvicorn.access"):
        logging.getLogger(name).setLevel(logging.WARNING)


def get_request_id() -> str:
    """Return the current request_id (or '-' outside a request context)."""
    return request_id_var.get()
