"""Log proxy request metadata and reject non-read HTTP methods."""

from __future__ import annotations

import email.message
import json
import logging
import re
import socket
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from mitmproxy import http


SOCKET_PATH = "/run/assistant-web-monitoring/events.sock"
COMPONENT = "assistant_web_proxy"
ALLOWED_METHODS = {"GET", "HEAD"}
POST_PATH_PREFIXES = {
    "chatgpt.com": (
        "/backend-api/codex/responses",
        "/backend-api/codex/guardian",
        "/backend-api/ps/mcp",
    ),
    "chat.openai.com": (
        "/backend-api/codex/responses",
        "/backend-api/codex/guardian",
        "/backend-api/ps/mcp",
    ),
    "auth.openai.com": ("/oauth/token", "/oauth/revoke"),
}
MAX_URL_CHARS = 16_384
MAX_EVENT_BYTES = 96 * 1024
MAX_RESPONSE_TEXT_CHARS = 16_000
REQUEST_HEADER_ALLOWLIST = {"accept", "accept-language", "content-type", "user-agent", "sec-fetch-dest"}
RESPONSE_HEADER_ALLOWLIST = {
    "cache-control", "content-language", "content-length", "content-type",
    "etag", "expires", "last-modified", "server", "vary",
}
TEXT_CONTENT_TYPES = ("text/", "application/json", "application/xml", "application/xhtml+xml")
NO_CONTENT_HOSTS = (
    "openai.com", "chatgpt.com", "anthropic.com", "claude.ai",
    "generativelanguage.googleapis.com", "gemini.google.com",
)
SENSITIVE_QUERY_NAME = re.compile(r"(token|secret|password|credential|session|auth|api.?key|^code$)", re.I)


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_url(url: str) -> str:
    """Keep path and query for audit, while omitting URL credentials/fragments."""
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    if parsed.port:
        host = f"{host}:{parsed.port}"
    query = urlencode([
        (key, "[REDACTED]" if SENSITIVE_QUERY_NAME.search(key) else value)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True)
    ])
    sanitized = urlunsplit((parsed.scheme, host, parsed.path, query, ""))
    return sanitized[:MAX_URL_CHARS]


def selected_headers(headers: object, allowlist: set[str]) -> dict[str, str]:
    safe: dict[str, str] = {}
    try:
        for name, value in headers.items():
            normalized = str(name).lower()
            if normalized in allowlist:
                safe[normalized] = str(value)[:512]
                if len(safe) >= 16:
                    break
    except (AttributeError, TypeError):
        return {}
    return safe


def response_text(flow: http.HTTPFlow) -> str:
    if not flow.response or not flow.request:
        return ""
    if flow.request.method.upper() not in {"GET", "HEAD"}:
        return ""
    host = flow.request.pretty_host.lower().rstrip(".")
    if any(host == suffix or host.endswith("." + suffix) for suffix in NO_CONTENT_HOSTS):
        return ""
    content_type = flow.response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if not content_type.startswith(TEXT_CONTENT_TYPES):
        return ""
    content = flow.response.content or b""
    if not content:
        return ""
    header = email.message.Message()
    header["content-type"] = flow.response.headers.get("content-type", "")
    charset = header.get_content_charset() or "utf-8"
    try:
        return content[:64 * 1024].decode(charset, "replace")[:MAX_RESPONSE_TEXT_CHARS]
    except LookupError:
        return content[:64 * 1024].decode("utf-8", "replace")[:MAX_RESPONSE_TEXT_CHARS]


def is_approved_post(url: str, host: str) -> bool:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.port not in (None, 443):
        return False
    path = parsed.path or "/"
    return any(
        path == prefix or path.startswith(prefix + "/")
        for prefix in POST_PATH_PREFIXES.get(host.lower().rstrip("."), ())
    )


def emit(event_name: str, **fields: object) -> bool:
    record = {"component": COMPONENT, "timestamp": timestamp(), "event": event_name, **fields}
    payload = json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sender:
            sender.settimeout(0.25)
            sender.sendto(payload, SOCKET_PATH)
        return True
    except OSError as exc:
        logging.error("could not send web activity event to monitor: %s", exc)
        return False


class ReadOnlyMethods:
    def http_connect(self, flow: http.HTTPFlow) -> None:
        # This records CONNECT destinations even when mitmproxy tunnels the TLS
        # session without decrypting it (for example, ignored model endpoints).
        authority = flow.request.host
        if flow.request.port:
            authority = f"{authority}:{flow.request.port}"
        logged = emit("tunnel_requested", flow_id=flow.id, host=flow.request.host,
                      port=flow.request.port, authority=authority)
        if not logged:
            flow.response = http.Response.make(503, b"Web activity monitor unavailable.\n")

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        method = flow.request.method.upper()
        fields = {
            "flow_id": flow.id,
            "method": method,
            "url": safe_url(flow.request.url),
            "host": flow.request.pretty_host,
        }
        host = flow.request.pretty_host.lower().rstrip(".")
        if method == "POST" and is_approved_post(flow.request.url, host):
            fields["method_exception"] = True
            if not emit("request_started", **fields):
                flow.response = http.Response.make(503, b"Web activity monitor unavailable.\n")
            return
        if method not in ALLOWED_METHODS:
            emit("method_rejected", **fields, status=405)
            logging.warning("blocked web proxy request method=%s host=%s", method, flow.request.pretty_host)
            flow.response = http.Response.make(
                405,
                b"This proxy only permits GET and HEAD requests.\n",
                {"Content-Type": "text/plain; charset=utf-8"},
            )
            return
        if not emit("request_started", **fields):
            flow.response = http.Response.make(503, b"Web activity monitor unavailable.\n")

    def response(self, flow: http.HTTPFlow) -> None:
        if not flow.request or flow.request.method.upper() == "CONNECT":
            return
        fields: dict[str, object] = dict(
            request_headers=selected_headers(flow.request.headers, REQUEST_HEADER_ALLOWLIST),
            response_headers=selected_headers(flow.response.headers, RESPONSE_HEADER_ALLOWLIST) if flow.response else {},
            response_bytes=len(flow.response.content or b"") if flow.response else 0,
        )
        body = response_text(flow)
        if body:
            fields["content_text"] = body
            fields["content_truncated"] = len(flow.response.content or b"") > 64 * 1024 or len(body) >= MAX_RESPONSE_TEXT_CHARS
        emit(
            "request_completed",
            flow_id=flow.id,
            method=flow.request.method.upper(),
            url=safe_url(flow.request.url),
            host=flow.request.pretty_host,
            status=flow.response.status_code if flow.response else None,
            **fields,
        )

    def error(self, flow: http.HTTPFlow) -> None:
        if not flow.request or flow.request.method.upper() == "CONNECT":
            return
        emit(
            "request_failed",
            flow_id=flow.id,
            method=flow.request.method.upper(),
            url=safe_url(flow.request.url),
            host=flow.request.pretty_host,
            error=str(flow.error)[:2000] if flow.error else "unknown error",
        )


addons = [ReadOnlyMethods()]
