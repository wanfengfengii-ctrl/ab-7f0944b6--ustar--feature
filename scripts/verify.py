#!/usr/bin/env python3
"""One-shot verification used by the Compose ``verify`` service.

Steps, each of which must pass:
  1. byte-compile the application ("build" check)
  2. run the full pytest suite
  3. boot the real HTTP server and run smoke scenarios:
       - a valid bundle                       -> 200 + correct bundleSha256
       - a header with a corrupted checksum   -> 422 bad_checksum
       - two members sharing one path         -> 409 duplicate_path
       - a request with no manifest header    -> 200 (legacy contract)
       - a valid BUNDLE.MANIFEST declaration  -> 200 + manifestSha256
       - a declared digest that does not hold -> 409 manifest_*
       - a member missing from the declaration-> 409 manifest_missing

Exits 0 only when everything passes; the first failure is reported and
the process exits 1.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import socket
import struct
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from app.server import MANIFEST_HEADER  # noqa: E402
from tests.manifest_helpers import bundle_with_manifest, manifest_text  # noqa: E402
from tests.tarbuilder import archive, file_member  # noqa: E402

PORT = int(os.environ.get("VERIFY_PORT", "8099"))


def step(title: str) -> None:
    print(f"\n== verify: {title} ==", flush=True)


def fail(title: str, detail: str) -> None:
    print(f"FAIL: {title}: {detail}", flush=True)
    sys.exit(1)


def run(cmd: list[str], title: str, env: dict | None = None) -> None:
    step(title)
    print(f"$ {' '.join(cmd)}", flush=True)
    full_env = dict(os.environ)
    full_env["PYTHONDONTWRITEBYTECODE"] = "1"
    if env:
        full_env.update(env)
    result = subprocess.run(cmd, cwd=ROOT, env=full_env)
    if result.returncode != 0:
        fail(title, f"exit code {result.returncode}")


def wait_for_health(port: int, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                conn.request("GET", "/health")
                resp = conn.getresponse()
                if resp.status == 200:
                    return
                last = f"status {resp.status}"
        except OSError as exc:
            last = str(exc)
        time.sleep(0.2)
    fail("server boot", f"never became healthy ({last})")


def post(port: int, payload: bytes, manifest_digest: str | None = None):
    headers = {"Content-Type": "application/x-tar"}
    if manifest_digest is not None:
        headers[MANIFEST_HEADER] = manifest_digest
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("POST", "/api/bundles/attest", body=payload, headers=headers)
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    return resp.status, json.loads(body)


def main() -> None:
    run([sys.executable, "-m", "compileall", "-q", "app"], "byte-compile app")
    run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"],
        "code tests")

    step("boot server for smoke tests")
    env = dict(os.environ, PORT=str(PORT), HOST="127.0.0.1")
    server = subprocess.Popen(
        [sys.executable, "-m", "app.server"], cwd=ROOT, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        wait_for_health(PORT)

        # --- valid bundle ------------------------------------------------
        step("smoke: valid bundle")
        files = [(b"readme.txt", b"hello\n"), (b"dir/data.bin", b"\x00\x01\x02")]
        payload = archive(*(file_member(n, c) for n, c in files))
        status, doc = post(PORT, payload)
        if status != 200:
            fail("valid bundle", f"expected 200, got {status}: {doc}")
        expected = hashlib.sha256()
        for name, content in sorted(files):
            expected.update(struct.pack(">I", len(name)))
            expected.update(name)
            expected.update(struct.pack(">Q", len(content)))
            expected.update(hashlib.sha256(content).digest())
        if doc.get("bundleSha256") != expected.hexdigest():
            fail("valid bundle", "bundleSha256 does not match independent digest")
        if [e["path"] for e in doc["entries"]] != ["dir/data.bin", "readme.txt"]:
            fail("valid bundle", "manifest order/paths incorrect")
        print(f"OK  200 bundleSha256={doc['bundleSha256']}", flush=True)

        # --- corrupted header checksum -----------------------------------
        step("smoke: bad header checksum")
        member = bytearray(file_member(b"f", b"x"))
        member[200] ^= 0x01  # damage header without updating its checksum
        bad_cksum = bytes(member) + b"\x00" * 1024
        status, doc = post(PORT, bad_cksum)
        if status != 422 or doc.get("error", {}).get("category") != "bad_checksum":
            fail("bad checksum", f"expected 422 bad_checksum, got {status}: {doc}")
        if "entries" in doc:
            fail("bad checksum", "partial manifest leaked into error response")
        print(f"OK  422 category=bad_checksum entry={doc['error']['entry']}",
              flush=True)

        # --- duplicate path ----------------------------------------------
        step("smoke: duplicate path conflict")
        dup = archive(file_member(b"same/path", b"a"),
                      file_member(b"same/path", b"b"))
        status, doc = post(PORT, dup)
        if status != 409 or doc.get("error", {}).get("category") != "duplicate_path":
            fail("path conflict", f"expected 409 duplicate_path, got {status}: {doc}")
        if "entries" in doc:
            fail("path conflict", "partial manifest leaked into error response")
        print("OK  409 category=duplicate_path entry=2", flush=True)

        # --- compatible request: no manifest header ---------------------
        step("smoke: legacy request without manifest header")
        files = [(b"readme.txt", b"hello\n"), (b"dir/data.bin", b"\x00\x01\x02")]
        payload = archive(*(file_member(n, c) for n, c in files))
        status, doc = post(PORT, payload)
        if status != 200:
            fail("legacy request", f"expected 200, got {status}: {doc}")
        if "manifestSha256" in doc:
            fail("legacy request", "manifestSha256 leaked without header")
        print("OK  200 legacy contract preserved", flush=True)

        # --- valid BUNDLE.MANIFEST declaration --------------------------
        step("smoke: valid bundle manifest")
        manifest_files = {b"cfg/a.ini": b"[core]\n", b"readme.txt": b"hi\n"}
        payload, declared = bundle_with_manifest(manifest_files)
        status, doc = post(PORT, payload, manifest_digest=declared)
        if status != 200:
            fail("valid manifest", f"expected 200, got {status}: {doc}")
        if doc.get("manifestSha256") != declared:
            fail("valid manifest", "manifestSha256 mismatch")
        if doc["manifestSha256"] != hashlib.sha256(
                manifest_text(manifest_files)).hexdigest():
            fail("valid manifest", "reported digest is not the raw-byte digest")
        paths = [e["path"] for e in doc["entries"]]
        if paths != ["BUNDLE.MANIFEST", "cfg/a.ini", "readme.txt"]:
            fail("valid manifest", f"unexpected entries: {paths}")
        print(f"OK  200 manifestSha256={declared}", flush=True)

        # --- digest conflict: header pins the wrong manifest digest -----
        step("smoke: manifest digest mismatch")
        payload, _ = bundle_with_manifest(manifest_files)
        status, doc = post(PORT, payload, manifest_digest="0" * 64)
        if status != 409 or doc.get("error", {}).get(
                "category") != "manifest_digest_mismatch":
            fail("manifest digest mismatch",
                 f"expected 409 manifest_digest_mismatch, got {status}: {doc}")
        if "entries" in doc:
            fail("manifest digest mismatch",
                 "partial manifest leaked into error response")
        print("OK  409 category=manifest_digest_mismatch", flush=True)

        # --- digest conflict: one declared item digest is wrong ---------
        step("smoke: manifest item digest mismatch")
        lying = manifest_text(
            {b"cfg/a.ini": (hashlib.sha256(b"tampered").digest(),
                            len(b"[core]\n")),
             b"readme.txt": b"hi\n"}
        )
        payload = archive(
            file_member(b"cfg/a.ini", b"[core]\n"),
            file_member(b"readme.txt", b"hi\n"),
            file_member(b"BUNDLE.MANIFEST", lying),
        )
        status, doc = post(
            PORT, payload, manifest_digest=hashlib.sha256(lying).hexdigest()
        )
        if status != 409 or doc.get("error", {}).get(
                "category") != "manifest_digest_item_mismatch":
            fail("item digest mismatch",
                 f"expected 409 manifest_digest_item_mismatch, got {status}: {doc}")
        if doc["error"].get("path") != "cfg/a.ini":
            fail("item digest mismatch", f"wrong path reported: {doc['error']}")
        print("OK  409 category=manifest_digest_item_mismatch path=cfg/a.ini",
              flush=True)

        # --- manifest omission: member not covered by the declaration ---
        step("smoke: manifest missing entry")
        text = manifest_text({b"readme.txt": b"hi\n"})
        payload = archive(
            file_member(b"readme.txt", b"hi\n"),
            file_member(b"unlisted.bin", b"x"),
            file_member(b"BUNDLE.MANIFEST", text),
        )
        status, doc = post(
            PORT, payload, manifest_digest=hashlib.sha256(text).hexdigest()
        )
        if status != 409 or doc.get("error", {}).get(
                "category") != "manifest_missing":
            fail("manifest omission",
                 f"expected 409 manifest_missing, got {status}: {doc}")
        if doc["error"].get("path") != "unlisted.bin":
            fail("manifest omission", f"wrong path reported: {doc['error']}")
        if "entries" in doc:
            fail("manifest omission",
                 "partial manifest leaked into error response")
        print("OK  409 category=manifest_missing path=unlisted.bin", flush=True)
    finally:
        server.terminate()
        try:
            out = server.communicate(timeout=5)[0]
        except subprocess.TimeoutExpired:
            server.kill()
            out = server.communicate()[0]
        if server.returncode not in (0, -15):
            print(out, flush=True)

    print("\nALL VERIFICATION STEPS PASSED", flush=True)


if __name__ == "__main__":
    main()
