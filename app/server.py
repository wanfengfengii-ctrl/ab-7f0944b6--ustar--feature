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

from .tarutil import (
    MAX_BUNDLE_BYTES,
    ManifestError,
    TarError,
    attest,
)

HEALTH_PATH = "/health"
ATTEST_PATH = "/api/bundles/attest"
TAR_CONTENT_TYPE = "application/x-tar"
MANIFEST_HEADER = "X-Bundle-Manifest-Sha256"
_SHA256_LOWER = re.compile(r"[0-9a-f]{64}")

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
    "duplicate_path": HTTPStatus.CONFLICT,
    "unsupported_media_type": HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
    # BUNDLE.MANIFEST declaration failures.
    "malformed_manifest": HTTPStatus.UNPROCESSABLE_ENTITY,
    "manifest_unsorted": HTTPStatus.UNPROCESSABLE_ENTITY,
    "manifest_duplicate": HTTPStatus.UNPROCESSABLE_ENTITY,
    "manifest_digest_mismatch": HTTPStatus.CONFLICT,
    "manifest_digest_item_mismatch": HTTPStatus.CONFLICT,
    "manifest_size_mismatch": HTTPStatus.CONFLICT,
    "manifest_missing": HTTPStatus.CONFLICT,
    "manifest_extra": HTTPStatus.CONFLICT,
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
                    entry: int | None = None,
                    line: int | None = None,
                    path: str | None = None) -> None:
        err = {"category": category, "message": message}
        if entry is not None:
            err["entry"] = entry
        if line is not None:
            err["line"] = line
        if path is not None:
            err["path"] = path
        self._send_json(status, {"error": err})

    def _send_tar_error(self, exc: TarError) -> None:
        status = _STATUS_FOR_CATEGORY.get(
            exc.category, HTTPStatus.UNPROCESSABLE_ENTITY
        )
        self._send_error(status, exc.category, exc.message, exc.entry)

    def _send_manifest_error(self, exc: ManifestError) -> None:
        status = _STATUS_FOR_CATEGORY.get(
            exc.category, HTTPStatus.UNPROCESSABLE_ENTITY
        )
        self._send_error(
            status, exc.category, exc.message, line=exc.line, path=exc.path
        )

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

        # Optional pre-registration pin: exactly 64 lowercase hex chars.
        header_values = self.headers.get_all(MANIFEST_HEADER) or []
        manifest_sha256: str | None = None
        if len(header_values) > 1:
            self._send_error(
                HTTPStatus.BAD_REQUEST, "bad_request",
                f"{MANIFEST_HEADER} must be given at most once",
            )
            return
        if header_values:
            value = header_values[0]
            if not _SHA256_LOWER.fullmatch(value):
                self._send_error(
                    HTTPStatus.BAD_REQUEST, "bad_request",
                    f"{MANIFEST_HEADER} must be 64 lowercase hex characters",
                )
                return
            manifest_sha256 = value

        try:
            result = attest(data, manifest_sha256=manifest_sha256)
        except TarError as exc:
            self._send_tar_error(exc)
            return
        except ManifestError as exc:
            self._send_manifest_error(exc)
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
