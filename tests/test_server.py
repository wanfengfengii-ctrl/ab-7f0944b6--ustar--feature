"""End-to-end tests against the real HTTP server (stdlib only)."""

from __future__ import annotations

import hashlib
import http.client
import threading

import pytest

from app.server import ATTEST_PATH, HEALTH_PATH, build_server

from .tarbuilder import archive, file_member


@pytest.fixture()
def server():
    srv = build_server("127.0.0.1", 0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    host, port = srv.server_address[:2]
    try:
        yield host, port
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=5)


def post_tar(host, port, payload: bytes, *, content_type="application/x-tar",
             extra_headers=None):
    conn = http.client.HTTPConnection(host, port, timeout=10)
    headers = {"Content-Type": content_type}
    if extra_headers:
        headers.update(extra_headers)
    conn.request("POST", ATTEST_PATH, body=payload, headers=headers)
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    return resp, body


import json  # noqa: E402


def test_health(server):
    host, port = server
    conn = http.client.HTTPConnection(host, port, timeout=10)
    conn.request("GET", HEALTH_PATH)
    resp = conn.getresponse()
    assert resp.status == 200
    assert json.loads(resp.read())["status"] == "ok"
    conn.close()


def test_valid_bundle_roundtrip(server):
    payload = archive(
        file_member(b"dir/a.bin", b"hello"),
        file_member(b"root.txt", b"world"),
    )
    resp, body = post_tar(host := server[0], server[1], payload)
    assert resp.status == 200, body
    doc = json.loads(body)
    assert [e["path"] for e in doc["entries"]] == ["dir/a.bin", "root.txt"]
    assert doc["entries"][0]["sha256"] == hashlib.sha256(b"hello").hexdigest()
    assert len(doc["bundleSha256"]) == 64


def test_bad_checksum_returns_locatable_error(server):
    member = bytearray(file_member(b"f", b"x"))
    member[300] ^= 0x01  # header damage, stale checksum
    payload = bytes(member) + b"\x00" * 1024
    resp, body = post_tar(*server, payload)
    assert resp.status == 422
    err = json.loads(body)["error"]
    assert err["category"] == "bad_checksum"
    assert err["entry"] == 1
    assert "entries" not in json.loads(body)


def test_duplicate_path_conflict(server):
    payload = archive(
        file_member(b"f", b"a"),
        file_member(b"f", b"b"),
    )
    resp, body = post_tar(*server, payload)
    assert resp.status == 409
    assert json.loads(body)["error"]["category"] == "duplicate_path"


def test_wrong_content_type_rejected(server):
    resp, body = post_tar(*server, b"x" * 1024,
                          content_type="application/octet-stream")
    assert resp.status == 415
    assert json.loads(body)["error"]["category"] == "unsupported_media_type"


def test_content_type_with_charset_accepted(server):
    payload = archive(file_member(b"f", b"x"))
    resp, body = post_tar(
        *server, payload,
        content_type="application/x-tar; charset=binary",
    )
    assert resp.status == 200, body


def test_gzip_content_encoding_rejected(server):
    resp, body = post_tar(*server, b"\x1f\x8bzz",
                          extra_headers={"Content-Encoding": "gzip"})
    assert resp.status == 415


def test_transfer_encoding_rejected(server):
    # Both headers present: the ambiguous framing must be refused outright.
    resp, body = post_tar(
        *server, b"x" * 512,
        extra_headers={"Transfer-Encoding": "chunked"},
    )
    assert resp.status == 400
    assert json.loads(body)["error"]["category"] == "bad_request"


def test_oversize_declared_length_rejected(server):
    host, port = server
    conn = http.client.HTTPConnection(host, port, timeout=10)
    conn.request(
        "POST", ATTEST_PATH, body=b"",
        headers={"Content-Type": "application/x-tar",
                 "Content-Length": "9000000"},
    )
    resp = conn.getresponse()
    assert resp.status == 413
    assert json.loads(resp.read())["error"]["category"] == "payload_too_large"
    conn.close()


def test_truncated_request_body_rejected(server):
    host, port = server
    conn = http.client.HTTPConnection(host, port, timeout=10)
    conn.putrequest("POST", ATTEST_PATH)
    conn.putheader("Content-Type", "application/x-tar")
    conn.putheader("Content-Length", "2048")
    conn.endheaders()
    conn.send(b"\x00" * 512)  # claim 2048, send 512 then half-close
    conn.sock.shutdown(1)  # SHUT_WR: server sees EOF and replies
    resp = conn.getresponse()
    assert resp.status == 400
    assert json.loads(resp.read())["error"]["category"] == "truncated"
    conn.close()


def test_unknown_route_404(server):
    host, port = server
    conn = http.client.HTTPConnection(host, port)
    conn.request("GET", "/nope")
    assert conn.getresponse().status == 404
    conn.close()


def test_error_never_contains_partial_manifest(server):
    # Trailing non-zero garbage after a valid member: the member itself
    # parsed fine, yet the response must not leak it.
    tail = bytearray(512)
    tail[10] = 1
    payload = archive(file_member(b"f", b"ok"), tail=bytes(tail))
    resp, body = post_tar(*server, payload)
    assert resp.status == 422
    doc = json.loads(body)
    assert "entries" not in doc
    assert doc["error"]["category"] == "trailing_data"
