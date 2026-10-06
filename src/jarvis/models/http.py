"""Tiny stdlib HTTP JSON client with structured, classified failures."""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any

from jarvis.core.models import ModelError, ModelErrorClass
from jarvis.security.redact import REDACTOR


@dataclass
class HttpFailure(Exception):
    error: ModelError
    status: int | None = None


def _opener(use_env_proxy: bool) -> urllib.request.OpenerDirector:
    handlers: list[urllib.request.BaseHandler] = []
    if not use_env_proxy:
        handlers.append(urllib.request.ProxyHandler({}))  # local endpoints must bypass proxies
    return urllib.request.build_opener(*handlers)


def classify_http_error(status: int, body: str, backend_id: str) -> ModelError:
    low = body.lower()
    if status in (401, 403):
        return ModelError(cls=ModelErrorClass.AUTH, message=f"authentication failed (HTTP {status})",
                          backend_id=backend_id)
    if status == 404 and "model" in low:
        return ModelError(cls=ModelErrorClass.MODEL_MISSING, message="model not found on server",
                          backend_id=backend_id)
    if status == 429:
        return ModelError(cls=ModelErrorClass.RATE_LIMITED, message="rate limited (HTTP 429)",
                          retryable=True, backend_id=backend_id)
    if status >= 500:
        return ModelError(cls=ModelErrorClass.INTERNAL, message=f"server error (HTTP {status})",
                          retryable=True, backend_id=backend_id)
    return ModelError(cls=ModelErrorClass.BAD_RESPONSE, message=f"unexpected HTTP {status}",
                      backend_id=backend_id)


def request_json(
    method: str,
    url: str,
    *,
    backend_id: str,
    body: Mapping[str, Any] | None = None,
    headers: Mapping[str, str] | None = None,
    timeout: float,
    use_env_proxy: bool,
) -> Any:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with _opener(use_env_proxy).open(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        text = ""
        try:
            text = exc.read().decode("utf-8", errors="replace")[:500]
        except OSError:
            pass
        raise HttpFailure(classify_http_error(exc.code, text, backend_id), exc.code) from exc
    except TimeoutError as exc:
        raise HttpFailure(ModelError(cls=ModelErrorClass.TIMEOUT, message=f"timed out after {timeout:.0f}s",
                                     retryable=True, backend_id=backend_id)) from exc
    except urllib.error.URLError as exc:
        reason = exc.reason
        if isinstance(reason, (TimeoutError, socket.timeout)):
            raise HttpFailure(ModelError(cls=ModelErrorClass.TIMEOUT, message="connection timed out",
                                         retryable=True, backend_id=backend_id)) from exc
        raise HttpFailure(ModelError(
            cls=ModelErrorClass.SERVER_UNREACHABLE,
            message=REDACTOR.scrub_text(f"cannot reach server: {reason}"),
            retryable=True, backend_id=backend_id)) from exc
    except OSError as exc:
        raise HttpFailure(ModelError(cls=ModelErrorClass.SERVER_UNREACHABLE,
                                     message=REDACTOR.scrub_text(f"network error: {exc}"),
                                     retryable=True, backend_id=backend_id)) from exc
    try:
        return json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError as exc:
        raise HttpFailure(ModelError(cls=ModelErrorClass.BAD_RESPONSE, message="response was not valid JSON",
                                     backend_id=backend_id)) from exc


def stream_ndjson(
    url: str,
    *,
    backend_id: str,
    body: Mapping[str, Any],
    timeout: float,
    use_env_proxy: bool,
) -> Iterator[dict[str, Any]]:
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with _opener(use_env_proxy).open(req, timeout=timeout) as resp:
            for line in resp:
                line = line.strip()
                if line:
                    yield json.loads(line)
    except urllib.error.HTTPError as exc:
        raise HttpFailure(classify_http_error(exc.code, "", backend_id), exc.code) from exc
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
        raise HttpFailure(ModelError(cls=ModelErrorClass.SERVER_UNREACHABLE,
                                     message=REDACTOR.scrub_text(f"stream failed: {exc}"),
                                     retryable=True, backend_id=backend_id)) from exc
