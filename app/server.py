"""HTTP service exposing the TAR attestation endpoint.

Endpoints:
  GET  /health              -> liveness probe
  POST /api/bundles/attest  -> strict USTAR attestation

Only the Python standard library is required.
"""

from __future__ import annotations

import json
import os
import re
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .tarutil import MAX_BUNDLE_BYTES, TarError, attest

HEALTH_PATH = "/health"
ATTEST_PATH = "/api/bundles/attest"
TAR_CONTENT_TYPE = "application/x-tar"
MANIFEST_DIGEST_HEADER = "X-Bundle-Manifest-Sha256"
_LOWERCASE_SHA256 = re.compile(r"[0-9a-f]{64}")

# Category -> HTTP status.  Nothing here ever returns a partial manifest.
_STATUS_FOR_CATEGORY = {
    "payload_too_large": HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
    "content_too_large": HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
    "empty_archive": HTTPStatus.BAD_REQUEST,
    "truncated": HTTPStatus.BAD_REQUEST,
    "bad_checksum": HTTPStatus.UNPROCESSABLE_ENTITY,
    "non_ustar": HTTPStatus.UNPROCESSABLE_ENTITY,
    "unsupported_type": HTTPStatus.UNPROCESSABLE_ENTITY,
    "malformed_header": HTTPStatus.UNPROCESSABLE_ENTITY,
    "bad_padding": HTTPStatus.UNPROCESSABLE_ENTITY,
    "bad_terminator": HTTPStatus.UNPROCESSABLE_ENTITY,
    "trailing_data": HTTPStatus.UNPROCESSABLE_ENTITY,
    "invalid_path": HTTPStatus.UNPROCESSABLE_ENTITY,
    "too_many_entries": HTTPStatus.UNPROCESSABLE_ENTITY,
    "bad_manifest": HTTPStatus.UNPROCESSABLE_ENTITY,
    "manifest_conflict": HTTPStatus.CONFLICT,
    "manifest_digest_mismatch": HTTPStatus.CONFLICT,
    "duplicate_path": HTTPStatus.CONFLICT,
    "unsupported_media_type": HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
}


class AttestHandler(BaseHTTPRequestHandler):
    server_version = "TarAttest/1.0"

    # Silence the default stderr logging; structured JSON goes to stdout.
    def log_message(self, fmt: str, *args) -> None:  # noqa: D401
        return

    # -- helpers -----------------------------------------------------------

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, status: int, category: str, message: str,
                    entry: int | None = None, line: int | None = None) -> None:
        err = {"category": category, "message": message}
        if entry is not None:
            err["entry"] = entry
        if line is not None:
            err["line"] = line
        self._send_json(status, {"error": err})

    def _send_tar_error(self, exc: TarError) -> None:
        status = _STATUS_FOR_CATEGORY.get(
            exc.category, HTTPStatus.UNPROCESSABLE_ENTITY
        )
        self._send_error(status, exc.category, exc.message, exc.entry, exc.line)

    # -- routing -----------------------------------------------------------

    def do_GET(self) -> None:
        if self.path.split("?", 1)[0] == HEALTH_PATH:
            self._send_json(HTTPStatus.OK, {"status": "ok"})
            return
        self._send_error(HTTPStatus.NOT_FOUND, "not_found", "unknown path")

    def do_POST(self) -> None:
        if self.path.split("?", 1)[0] != ATTEST_PATH:
            self._send_error(HTTPStatus.NOT_FOUND, "not_found", "unknown path")
            return
        self._handle_attest()

    def do_PUT(self) -> None:
        self._method_not_allowed()

    def do_DELETE(self) -> None:
        self._method_not_allowed()

    def _method_not_allowed(self) -> None:
        path = self.path.split("?", 1)[0]
        if path in (HEALTH_PATH, ATTEST_PATH):
            self._send_error(
                HTTPStatus.METHOD_NOT_ALLOWED, "method_not_allowed",
                "method not allowed",
            )
        else:
            self._send_error(HTTPStatus.NOT_FOUND, "not_found", "unknown path")

    # -- attestation -------------------------------------------------------

    def _handle_attest(self) -> None:
        ctype = self.headers.get("Content-Type", "")
        main_type = ctype.split(";", 1)[0].strip().lower()
        if main_type != TAR_CONTENT_TYPE:
            self._send_error(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                "unsupported_media_type",
                f"expected Content-Type {TAR_CONTENT_TYPE}",
            )
            return

        # Archives must be uncompressed: reject any transport encoding.
        encoding = self.headers.get("Content-Encoding", "").strip().lower()
        if encoding and encoding != "identity":
            self._send_error(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                "unsupported_media_type",
                "compressed or encoded payloads are not accepted",
            )
            return

        transfer_encoding = self.headers.get("Transfer-Encoding", "").strip()
        if transfer_encoding:
            self._send_error(
                HTTPStatus.BAD_REQUEST, "bad_request",
                "chunked/transfer-encoded requests are not accepted; "
                "send Content-Length instead",
            )
            return

        # Optional pre-registered digest of the in-bundle declaration
        # file.  Absent: the original contract applies unchanged.
        manifest_header = self.headers.get(MANIFEST_DIGEST_HEADER)
        expected_manifest_sha256: str | None = None
        if manifest_header is not None:
            expected_manifest_sha256 = manifest_header.strip()
            if not _LOWERCASE_SHA256.fullmatch(expected_manifest_sha256):
                self._send_error(
                    HTTPStatus.BAD_REQUEST, "bad_request",
                    f"{MANIFEST_DIGEST_HEADER} must be a lowercase "
                    "hex SHA-256 digest (64 characters)",
                )
                return

        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            self._send_error(
                HTTPStatus.BAD_REQUEST, "bad_request",
                "invalid Content-Length",
            )
            return
        if length < 0:
            self._send_error(
                HTTPStatus.LENGTH_REQUIRED, "length_required",
                "Content-Length is required",
            )
            return
        if length > MAX_BUNDLE_BYTES:
            self._send_error(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "payload_too_large",
                "archive exceeds 8 MiB",
            )
            self._drain(length)
            return

        data = self._read_exact(length)
        if data is None:
            # Framing is broken; do not attempt to reuse the connection.
            self.close_connection = True
            return

        try:
            result = attest(data, expected_manifest_sha256)
        except TarError as exc:
            self._send_tar_error(exc)
            return
        self._send_json(HTTPStatus.OK, result)

    def _read_exact(self, length: int) -> bytes | None:
        chunks: list[bytes] = []
        remaining = length
        while remaining > 0:
            chunk = self.rfile.read(min(65536, remaining))
            if not chunk:
                self._send_error(
                    HTTPStatus.BAD_REQUEST, "truncated",
                    "request body shorter than Content-Length",
                )
                return None
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _drain(self, length: int) -> None:
        remaining = length
        while remaining > 0:
            chunk = self.rfile.read(min(65536, remaining))
            if not chunk:
                return
            remaining -= len(chunk)


def build_server(host: str, port: int) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), AttestHandler)


def main() -> None:
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    server = build_server(host, port)
    print(f"TAR attestation service listening on {host}:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
