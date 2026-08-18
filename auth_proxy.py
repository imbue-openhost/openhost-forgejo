"""OpenHost auth proxy sidecar for Forgejo.

Sits between the OpenHost router and Forgejo.  When the router stamps
``X-OpenHost-Is-Owner: true`` on the inbound request (meaning the
visitor holds a valid session), this proxy adds
``X-Openhost-User: <owner>`` so Forgejo's reverse-proxy auth treats the
visitor as that account.  ``<owner>`` is the OpenHost owner's real
username (``OPENHOST_OWNER_USERNAME``), so they appear under their own
identity instead of a generic shared account; it falls back to
``operator`` when that value is missing, malformed, or reserved by
Forgejo (see ``_resolve_owner_username``).

Forgejo is configured with REVERSE_PROXY_AUTHENTICATION_USER set to
``X-Openhost-User``, so a valid stamped header authenticates the
visitor as that Forgejo user.  On the first such request, Forgejo
auto-creates the account (ENABLE_REVERSE_PROXY_AUTO_REGISTRATION =
true), which becomes user ID 1 and therefore admin.

Visitors who are not the owner get the request passed through with
NO ``X-Openhost-User`` header.  Forgejo then falls back to its normal
session/password auth flow at ``/user/login``.  The two paths coexist
without conflict.

Security model
==============

The OpenHost router is the sole authority for ``X-OpenHost-*`` headers.
Before forwarding any request to an app container, the router strips
all client-supplied ``X-OpenHost-*`` headers (see
``_sanitize_forwarded_headers`` in the platform's ``proxy.py``).  It
then re-adds ``X-OpenHost-Is-Owner: true`` only if the visitor's
``session_token`` cookie verified successfully.  This means:

  * A non-owner visitor **cannot** spoof the header — the router
    removes it before the request reaches us.
  * We can trust the header unconditionally, even on public paths.

We still strip ``X-Openhost-User`` from inbound requests as defence
in depth, and Forgejo's ``REVERSE_PROXY_TRUSTED_PROXIES = 127.0.0.1/32``
ensures only this sidecar's stamped header is honoured.

We also rewrite the ``Host`` header from ``X-Forwarded-Host``.  The
OpenHost router strips the original ``Host`` and puts the value the
client used in ``X-Forwarded-Host``; Forgejo's CSRF check compares the
inbound Host against its configured ROOT_URL, so we need the original
hostname forwarded.
"""

from __future__ import annotations

import http.client
import logging
import os
import re
import socket
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import AbstractSet, Iterable

OWNER_HEADER_NAME = "X-OpenHost-Is-Owner"
AUTH_HEADER_NAME = "X-Openhost-User"

# Forgejo username we map the OpenHost owner to when no usable OpenHost
# username is available.  Forgejo reserves ``admin`` as a system name, so
# we cannot use that; ``operator`` is a safe, valid fallback.
FALLBACK_OWNER_USERNAME = "operator"

# Names Forgejo reserves / refuses for normal accounts.  Mapping the
# owner to one of these would make reverse-proxy auto-registration fail,
# so we fall back instead.
RESERVED_USERNAMES = frozenset(
    {"admin", "ghost", "user", "me", "attachments", "assets", "explore", "issues", "pulls"}
)

# Forgejo usernames: alphanumeric plus -, _, . — must start/end with an
# alphanumeric and not look like a reserved/path-like token.  This mirrors
# Forgejo's own validation closely enough that anything we accept here will
# be accepted by reverse-proxy auto-registration.
_VALID_USERNAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,38}[a-zA-Z0-9]$|^[a-zA-Z0-9]$")


def _resolve_owner_username() -> str:
    """Return the Forgejo username to auto-log the OpenHost owner in as.

    Uses the OpenHost-provided owner username (``OPENHOST_OWNER_USERNAME``)
    so the visitor shows up under their real OpenHost identity rather than a
    generic shared account.  Falls back to ``operator`` when the value is
    missing, malformed, or reserved by Forgejo so auto-registration can't
    break.
    """
    raw = os.environ.get("OPENHOST_OWNER_USERNAME", "").strip()
    if not raw:
        return FALLBACK_OWNER_USERNAME
    if not _VALID_USERNAME_RE.match(raw):
        log_target = logging.getLogger(__name__)
        log_target.warning(
            "OPENHOST_OWNER_USERNAME=%r is not a valid Forgejo username; "
            "falling back to %r",
            raw,
            FALLBACK_OWNER_USERNAME,
        )
        return FALLBACK_OWNER_USERNAME
    if raw.lower() in RESERVED_USERNAMES:
        logging.getLogger(__name__).warning(
            "OPENHOST_OWNER_USERNAME=%r is reserved by Forgejo; falling back to %r",
            raw,
            FALLBACK_OWNER_USERNAME,
        )
        return FALLBACK_OWNER_USERNAME
    return raw
# Headers that must not be forwarded hop-by-hop (RFC 7230 §6.1) plus a few
# extras where we control the forwarding meaning.
HOP_BY_HOP_HEADERS = frozenset(
    h.lower()
    for h in (
        "Connection",
        "Keep-Alive",
        "Proxy-Authenticate",
        "Proxy-Authorization",
        "TE",
        "Trailer",
        "Transfer-Encoding",
        "Upgrade",
        # Host is dropped from the inbound request (it points at the
        # proxy, not the client's view of the URL); _proxy() then
        # explicitly forwards a Host header based on X-Forwarded-Host
        # so Forgejo's CSRF check sees the right origin.
        "Host",
    )
)

# Defence in depth: always strip these from inbound requests so a
# misconfigured router or direct container access can't inject auth.
# Also strip Authorization (the platform Bearer token) which Forgejo
# does not use but logs in access logs when passed as a query param
# or header, leaking the token.
ALWAYS_STRIP_HEADERS = frozenset(
    h.lower() for h in (OWNER_HEADER_NAME, AUTH_HEADER_NAME, "authorization")
)

logging.basicConfig(
    level=os.environ.get("AUTH_PROXY_LOG_LEVEL", "INFO"),
    format="[auth-proxy] %(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("auth_proxy")

# The Forgejo username the OpenHost owner is auto-logged in as.  Resolved
# once at startup from OPENHOST_OWNER_USERNAME (with a safe fallback).
OWNER_USERNAME = _resolve_owner_username()
log.info("Mapping OpenHost owner to Forgejo username %r", OWNER_USERNAME)


def _strip_headers(
    headers: Iterable[tuple[str, str]], drop: AbstractSet[str]
) -> list[tuple[str, str]]:
    drop_lower = {h.lower() for h in drop}
    return [(k, v) for k, v in headers if k.lower() not in drop_lower]


class AuthProxyHandler(BaseHTTPRequestHandler):
    forgejo_host: str = "127.0.0.1"
    forgejo_port: int = 3001

    # Route request logs through our logger so they're interleaved with
    # the module's own log lines, and suppress logs for the OpenHost
    # router's healthcheck path entirely (successful and otherwise) so
    # the liveness probes don't flood the container log with ~1
    # line/second.  /api/healthz is Forgejo's own health endpoint.
    def log_message(self, format: str, *args) -> None:  # noqa: A002, N802
        path = getattr(self, "path", "")
        if path.startswith("/api/healthz"):
            return
        log.info("%s - " + format, self.address_string(), *args)

    def do_GET(self) -> None:  # noqa: N802
        self._proxy()

    def do_HEAD(self) -> None:  # noqa: N802
        self._proxy()

    def do_POST(self) -> None:  # noqa: N802
        self._proxy()

    def do_PUT(self) -> None:  # noqa: N802
        self._proxy()

    def do_DELETE(self) -> None:  # noqa: N802
        self._proxy()

    def do_PATCH(self) -> None:  # noqa: N802
        self._proxy()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._proxy()

    # Cap on request- and response-body memory so a crafted or
    # buggy client cannot drive the proxy OOM by sending
    # `Content-Length: 2147483647`.  128 MiB is a soft tradeoff:
    # large enough to handle most web-UI repo imports / attachment
    # uploads, small enough to bound memory exposure when several
    # concurrent uploads are in flight.
    #
    # Pure git-over-HTTP push/pull traffic can exceed this for big
    # repos.  If you push large repos through the web proxy, either
    # raise this cap or stop using web-based git operations and use
    # personal-access-token auth with the standard ports.  The cap
    # is intentionally a class attribute so it can be overridden
    # in subclasses or by patching at startup.
    MAX_BODY_BYTES = 128 * 1024 * 1024

    # Read timeout on the client socket.  A slow-loris client dripping body
    # bytes over minutes would otherwise tie up a server thread indefinitely,
    # leading to thread exhaustion under concurrency.
    CLIENT_READ_TIMEOUT_SECONDS = 60

    def _safe_send_error(self, code: int, message: str) -> None:
        """Send an HTTP error, silently swallowing OSError.

        If the client has already disconnected, send_error will fail with
        BrokenPipeError (an OSError subclass).  We don't want that to bubble
        up as an unhandled exception — the request is already over.
        """
        try:
            self.send_error(code, message)
        except OSError as exc:
            log.debug("client disconnected before error response: %s", exc)

    def _proxy(self) -> None:
        # Apply a read timeout to the incoming socket so a slow client can't
        # hold a thread forever while sending the request body.
        try:
            self.connection.settimeout(self.CLIENT_READ_TIMEOUT_SECONDS)
        except OSError:
            # Very unlikely (socket already closed); nothing to recover.
            pass

        # Check owner status BEFORE stripping headers.  The router
        # guarantees this header is authentic (it strips all client-supplied
        # X-OpenHost-* headers and only re-adds this one after verifying
        # the session_token cookie).
        is_owner = (
            self.headers.get(OWNER_HEADER_NAME, "").lower() == "true"
        )

        # Strip (a) the auth header and owner header (never forward
        # router-internal headers to Forgejo), (b) hop-by-hop headers
        # (Connection, Transfer-Encoding, etc.), and (c) Content-Length
        # — we rebuild the body into a buffered request below and set a
        # fresh Content-Length from the actual bytes we send.
        cleaned_headers = _strip_headers(
            self.headers.items(),
            HOP_BY_HOP_HEADERS | ALWAYS_STRIP_HEADERS | {"content-length"},
        )

        # Rewrite Host from X-Forwarded-Host.  The OpenHost router
        # strips the original Host header and puts the value the
        # client actually used into X-Forwarded-Host.  Forgejo's CSRF
        # check compares the request's Host against its configured
        # ROOT_URL hostname; without this rewrite, every POST gets
        # rejected with "Bad Request: invalid CSRF token" because
        # Host arrives as 127.0.0.1 (the proxy address) instead of
        # forgejo.<zone>.
        #
        # Some inbound requests (e.g. the OpenHost router's own
        # liveness probe to /api/healthz) won't have X-Forwarded-Host
        # set.  We fall back to letting http.client set its default
        # (which points at the loopback target).  For health-check
        # paths Forgejo doesn't enforce a Host match anyway.
        forwarded_host = self.headers.get("X-Forwarded-Host")
        explicit_host_set = False
        if forwarded_host:
            cleaned_headers.append(("Host", forwarded_host))
            explicit_host_set = True

        if is_owner:
            # Map the OpenHost owner to their real OpenHost username
            # (OWNER_USERNAME, resolved from OPENHOST_OWNER_USERNAME) so
            # they appear under their own identity rather than a generic
            # shared account.  Forgejo reserves ``admin`` as a system
            # name, so a reserved/invalid value falls back to
            # ``operator``.  The user is auto-created on first owner
            # request via ENABLE_REVERSE_PROXY_AUTO_REGISTRATION and ends
            # up as user ID 1 (the Forgejo admin).
            cleaned_headers.append((AUTH_HEADER_NAME, OWNER_USERNAME))

        # Reject chunked (and any other non-identity) transfer encoding
        # outright.  We buffer the body into a new Content-Length request;
        # forwarding the raw chunked bytes as a plain body would corrupt
        # the upstream's parse, and implementing dechunking here duplicates
        # what the fronting OpenHost router (httpx-based) already does
        # before it reaches us.  501 is the correct status code: the
        # semantic issue is "we do not implement this transfer-coding", not
        # "please add Content-Length and try again" (which 411 would imply
        # and which would send a client into a retry loop).
        transfer_encoding = self.headers.get("Transfer-Encoding", "").lower().strip()
        if transfer_encoding and transfer_encoding != "identity":
            self._safe_send_error(501, "Transfer-Encoding not supported")
            return

        body: bytes | None = None
        content_length_header = self.headers.get("Content-Length")
        if content_length_header:
            try:
                length = int(content_length_header)
            except ValueError:
                self._safe_send_error(400, "invalid Content-Length")
                return
            if length < 0:
                self._safe_send_error(400, "negative Content-Length")
                return
            if length > self.MAX_BODY_BYTES:
                # Reject before allocating.  Without this cap a hostile client
                # could advertise a multi-GiB body and exhaust container RAM.
                self._safe_send_error(413, "request body too large")
                return
            if length > 0:
                try:
                    body = self.rfile.read(length)
                except (OSError, TimeoutError) as exc:
                    # Client dropped the connection or the socket timeout
                    # we set at the top of _proxy() fired.  Return 400 so
                    # the client sees a clean response instead of a raw
                    # traceback in the server log.
                    log.info("client read error: %s", exc)
                    self._safe_send_error(400, "request body read failed")
                    return
                if len(body) != length:
                    # Short read: the client closed the socket before
                    # sending the full body they promised.  We must not
                    # silently forward a truncated body with a shorter
                    # Content-Length header — Forgejo would accept the
                    # truncated request as if it were complete.
                    log.info(
                        "short read: expected %d bytes, got %d",
                        length,
                        len(body),
                    )
                    self._safe_send_error(400, "incomplete request body")
                    return
            else:
                body = b""
        elif self.command in ("POST", "PUT", "PATCH", "DELETE"):
            # Body method with no Content-Length and no Transfer-Encoding.
            # The HTTP spec says this means "no body" for a request (unlike a
            # response, which can use connection-close framing).  Forward an
            # empty body rather than blocking waiting for EOF, which would
            # otherwise let a slow client tie up a handler thread until the
            # 60s socket timeout fires.
            body = b""

        # The outer try/finally guarantees the upstream socket is always
        # released, even if conn.request() or getresponse() raises.  We use
        # putrequest/putheader rather than conn.request() so that duplicate
        # header names (e.g. multiple Set-Cookie on the request direction or
        # chained X-Forwarded-For entries) are each preserved — conn.request()
        # takes a dict and would silently collapse duplicates to the last
        # value.
        conn = http.client.HTTPConnection(
            self.forgejo_host, self.forgejo_port, timeout=60
        )
        try:
            try:
                # When we successfully rewrote Host from
                # X-Forwarded-Host, suppress http.client's automatic
                # Host header so our explicit one wins.  When we don't
                # have an X-Forwarded-Host (e.g. router liveness
                # probes), let http.client set its default Host
                # (``127.0.0.1:3001``) so the upstream request still
                # has a valid Host field — RFC 7230 §5.4 requires
                # one and Forgejo otherwise hangs / errors.
                # ``skip_accept_encoding`` avoids http.client adding
                # ``Accept-Encoding: identity`` if the client omitted
                # the header.
                conn.putrequest(
                    self.command,
                    self.path,
                    skip_host=explicit_host_set,
                    skip_accept_encoding=True,
                )
                for key, value in cleaned_headers:
                    conn.putheader(key, value)
                if body is not None:
                    conn.putheader("Content-Length", str(len(body)))
                conn.endheaders(message_body=body)
                upstream = conn.getresponse()
            except (OSError, http.client.HTTPException) as exc:
                log.warning("upstream error: %s", exc)
                self._safe_send_error(502, "Bad Gateway")
                return

            # Read the upstream body into memory, capped at the same
            # limit we enforce on request bodies.  A compromised or
            # misbehaving Forgejo streaming an oversized response could
            # otherwise exhaust container RAM.  ``read(MAX_BODY_BYTES + 1)``
            # lets us distinguish "cap reached, probably more available"
            # from "legitimate body just under the cap".
            try:
                payload = upstream.read(self.MAX_BODY_BYTES + 1)
            except (OSError, http.client.HTTPException) as exc:
                log.warning("upstream read error: %s", exc)
                self._safe_send_error(502, "Bad Gateway")
                try:
                    upstream.close()
                except Exception as close_exc:  # noqa: BLE001 - best effort
                    log.debug("upstream.close() after read error raised: %s", close_exc)
                return
            try:
                upstream.close()
            except Exception as exc:  # noqa: BLE001 - best effort only
                log.debug("upstream.close() raised (ignored): %s", exc)
            if len(payload) > self.MAX_BODY_BYTES:
                log.warning(
                    "upstream response exceeded %d bytes; returning 502",
                    self.MAX_BODY_BYTES,
                )
                self._safe_send_error(502, "upstream response too large")
                return

            # Forward upstream's status + headers.  We leave upstream's
            # Content-Length intact because for HEAD it's the only way the
            # client learns the size a real GET would return; for everything
            # else it matches len(payload) anyway since we just read the
            # whole body.  The whole block writes to the client socket, so a
            # disconnect here surfaces as OSError; swallow it the same way
            # we do for the body write below.
            #
            # ``upstream.reason`` can legitimately be None (RFC 9110 §6.2
            # allows a bare status line with no reason phrase); fall back
            # to an empty string so send_response doesn't emit
            # "HTTP/1.1 200 None".
            reason = upstream.reason or ""
            try:
                self.send_response(upstream.status, reason)
                for key, value in upstream.getheaders():
                    if key.lower() in HOP_BY_HOP_HEADERS:
                        continue
                    self.send_header(key, value)
                self.end_headers()
                # HEAD responses MUST NOT include a message body (RFC 9110
                # §9.3.2).  http.client already returns an empty payload for
                # HEAD but suppress the write unconditionally for clarity.
                if self.command != "HEAD":
                    self.wfile.write(payload)
            except OSError as exc:
                # BrokenPipeError, ConnectionResetError, TimeoutError, and
                # ECONNABORTED are all signals that the client went away.
                # Nothing we can do except log at debug and avoid crashing
                # the handler thread.
                log.debug("client disconnected mid-response: %s", exc)
        finally:
            conn.close()


class IPv4ThreadingServer(ThreadingHTTPServer):
    # OpenHost's router talks to the container over Docker's bridge network
    # on IPv4, so we explicitly bind IPv4 and don't advertise dual-stack
    # capability.  allow_reuse_address lets us come back up quickly after a
    # crash, daemon_threads ensures request threads don't keep the process
    # alive on shutdown.
    address_family = socket.AF_INET
    allow_reuse_address = True
    daemon_threads = True


def _port_from_env(name: str, default: int) -> int:
    """Read a port from an env var, with a clear error on non-integer input."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        port = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name}={raw!r} is not an integer: {exc}") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"{name}={raw!r} is out of range (1-65535)")
    return port


def main() -> int:
    try:
        listen_port = _port_from_env("AUTH_PROXY_LISTEN_PORT", 3000)
        forgejo_port = _port_from_env("FORGEJO_UPSTREAM_PORT", 3001)
    except ValueError as exc:
        log.error("invalid port configuration: %s", exc)
        return 1

    AuthProxyHandler.forgejo_port = forgejo_port

    try:
        server = IPv4ThreadingServer(("0.0.0.0", listen_port), AuthProxyHandler)
    except OSError as exc:
        log.error(
            "failed to bind auth-proxy listener on 0.0.0.0:%d: %s",
            listen_port,
            exc,
        )
        return 1
    log.info(
        "listening on 0.0.0.0:%d -> 127.0.0.1:%d",
        listen_port,
        forgejo_port,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
