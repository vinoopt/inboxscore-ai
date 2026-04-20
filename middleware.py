"""
Request context middleware for InboxScore.

Assigns a request_id to every HTTP request:
  - If the client sent an X-Request-ID header and it looks sane, we reuse it
    (useful for CDN/LB trace correlation). Otherwise we mint a UUID4.
  - Stores it in `request_id_var` so every log line in this request carries it.
  - Tags it on Sentry scope so errors show up with the same id.
  - Echoes it back as X-Request-ID response header.
  - Emits one structured access-log line per request on completion.

Middleware is added in app.py *after* CORS so CORS preflights still work; the
access log line is emitted even for 4xx/5xx paths.
"""

from __future__ import annotations

import logging
import re
import time
import uuid
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from logging_config import request_id_var

# Accept only printable ASCII, no spaces, max 64 chars — reject anything weird
# so a malicious client can't smuggle log-injection payloads via header.
_SAFE_RID = re.compile(r"^[A-Za-z0-9._\-]{1,64}$")

logger = logging.getLogger("inboxscore.access")


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Generate/propagate X-Request-ID and emit an access log line per request."""

    def __init__(self, app, sentry_enabled: bool = False) -> None:
        super().__init__(app)
        self._sentry_enabled = sentry_enabled

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        incoming = request.headers.get("x-request-id", "").strip()
        rid = incoming if incoming and _SAFE_RID.match(incoming) else uuid.uuid4().hex

        token = request_id_var.set(rid)

        # Tag Sentry so any captured exception in this request is labelled.
        if self._sentry_enabled:
            try:
                import sentry_sdk
                sentry_sdk.set_tag("request_id", rid)
            except Exception:  # never let instrumentation break a request
                pass

        start = time.perf_counter()
        status_code = 500  # pessimistic default if call_next raises
        response: Response | None = None
        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        finally:
            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            client_ip = request.client.host if request.client else "-"
            try:
                logger.info(
                    "http.request",
                    extra={
                        "method": request.method,
                        "path": request.url.path,
                        "query": request.url.query or "",
                        "status": status_code,
                        "duration_ms": duration_ms,
                        "client_ip": client_ip,
                        "user_agent": request.headers.get("user-agent", "")[:200],
                    },
                )
            except Exception:
                pass

            if response is not None:
                response.headers["X-Request-ID"] = rid

            request_id_var.reset(token)
