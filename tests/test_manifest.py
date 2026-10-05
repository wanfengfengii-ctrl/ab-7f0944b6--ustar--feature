"""Unit tests for BUNDLE.MANIFEST declaration parsing and verification."""

from __future__ import annotations

import hashlib

import pytest

from app.tarutil import (
    MANIFEST_PATH,
    TarError,
    attest,
    parse_manifest,
)

from .tarbuilder import archive, file_member


def member_with_manifest(files: dict[bytes, bytes], manifest: bytes) -> bytes:
    members = [file_member(name, content) for name, content in files.items()]
    members.append(file_member(MANIFEST_PATH, manifest))
    return archive(*members)


def declaration(files: dict[bytes, bytes]) -> bytes:
    """Build a well-formed manifest body (byte-sorted, LF-terminated)."""
    lines = []
    for path in sorted(files):
        content = files[path]
        lines.append(
            hashlib.sha256(content).hexdigest().encode("ascii")
            + b"\t" + str(len(content)).encode("ascii")
            + b"\t" + path
        )
    return b"\n".join(lines) + b"\n"


def bundle_with_manifest(files: dict[bytes, bytes], *,
                         manifest: bytes | None = None):
    if manifest is None:
        manifest = declaration(files)
    blob = member_with_manifest(files, manifest)
    return blob, hashlib.sha256(manifest).hexdigest()


# --------------------------------------------------------------------------
# parse_manifest format checks
# --------------------------------------------------------------------------


def test_parse_manifest_valid_lines():
    parsed = parse_manifest(b"a" * 64 + b"\t10\ta.txt\n"
                            + b"f" * 64 + b"\t0\tb\n")
    assert parsed[0][0] == b"a.txt"
    assert parsed[0][1] == 10
    assert parsed[1][1] == 0


def test_parse_manifest_requires_trailing_lf():
    raw = b"a" * 64 + b"\t1\ta"  # no terminating LF
    with pytest.raises(TarError) as exc:
        parse_manifest(raw)
    assert exc.value.category == "bad_manifest"
    assert exc.value.line == 1


@pytest.mark.parametrize(
    "raw,line",
    [
        # missing size field (only one tab)
        (b"a" * 64 + b"\ta.txt\n", 1),
        # too many fields
        (b"a" * 64 + b"\t1\ta\textra\n", 1),
        # uppercase digest
        (b"A" * 64 + b"\t1\ta\n", 1),
        # short digest
        (b"a" * 63 + b"\t1\ta\n", 1),
        # non-canonical decimal size (leading zero)
        (b"a" * 64 + b"\t01\ta\n", 1),
        # negative size
        (b"a" * 64 + b"\t-1\ta\n", 1),
        # empty line in the middle
        (b"a" * 64 + b"\t1\ta\n\n", 2),
        # dot segment path
        (b"a" * 64 + b"\t1\t./a\n", 1),
        # absolute path
        (b"a" * 64 + b"\t1\t/a\n", 1),
        # backslash
        (b"a" * 64 + b"\t1\ta\\b\n", 1),
        # manifest may not list itself
        (b"a" * 64 + b"\t14\tBUNDLE.MANIFEST\n", 1),
    ],
)
def test_parse_manifest_format_errors(raw, line):
    with pytest.raises(TarError) as exc:
        parse_manifest(raw)
    assert exc.value.category == "bad_manifest"
    assert exc.value.line == line


def test_parse_manifest_non_ascii_reports_line():
    raw = (b"a" * 64 + b"\t1\tok\n"
           + b"b" * 64 + b"\t1\t" + b"\xc3\xa9\n")  # é on line 2
    with pytest.raises(TarError) as exc:
        parse_manifest(raw)
    assert exc.value.category == "bad_manifest"
    assert exc.value.line == 2


def test_parse_manifest_unsorted_reports_first_offending_line():
    raw = (b"a" * 64 + b"\t1\tb\n"
           + b"c" * 64 + b"\t1\ta\n")
    with pytest.raises(TarError) as exc:
        parse_manifest(raw)
    assert exc.value.category == "bad_manifest"
    assert exc.value.line == 2


def test_parse_manifest_equal_neighbours_not_increasing():
    raw = (b"a" * 64 + b"\t1\ta\n"
           + b"c" * 64 + b"\t1\ta\n")
    with pytest.raises(TarError) as exc:
        parse_manifest(raw)
    assert exc.value.category == "bad_manifest"
    assert exc.value.line == 2


def test_parse_manifest_crlf_rejected():
    raw = b"a" * 64 + b"\t1\ta\r\n"
    with pytest.raises(TarError) as exc:
        parse_manifest(raw)
    assert exc.value.category == "bad_manifest"
    assert exc.value.line == 1


# --------------------------------------------------------------------------
# attest() with a pre-registered digest
# --------------------------------------------------------------------------


def test_attest_without_header_ignores_manifest_member():
    # Backwards compatibility: a manifest member is an ordinary file.
    files = {b"f": b"x"}
    blob = member_with_manifest(files, declaration(files))
    result = attest(blob)
    assert "manifestSha256" not in result
    assert [e["path"] for e in result["entries"]] == ["BUNDLE.MANIFEST", "f"]


def test_attest_valid_manifest_returns_manifest_sha256():
    files = {b"readme.txt": b"hello\n", b"dir/data.bin": b"\x00\x01"}
    blob, digest = bundle_with_manifest(files)
    result = attest(blob, digest)
    assert result["manifestSha256"] == digest
    assert [e["path"] for e in result["entries"]] == [
        "BUNDLE.MANIFEST", "dir/data.bin", "readme.txt",
    ]


def test_attest_empty_file_member_declared_with_zero_size():
    files = {b"empty": b""}
    blob, digest = bundle_with_manifest(files)
    result = attest(blob, digest)
    assert result["manifestSha256"] == digest


def test_attest_manifest_only_bundle_with_empty_declaration():
    # A bundle whose only member is BUNDLE.MANIFEST declares zero others.
    blob = member_with_manifest({}, b"")
    result = attest(blob, hashlib.sha256(b"").hexdigest())
    assert [e["path"] for e in result["entries"]] == ["BUNDLE.MANIFEST"]
    assert result["manifestSha256"] == hashlib.sha256(b"").hexdigest()


def test_attest_missing_manifest_member_conflicts():
    blob = archive(file_member(b"f", b"x"))
    with pytest.raises(TarError) as exc:
        attest(blob, "a" * 64)
    assert exc.value.category == "manifest_conflict"


def test_attest_wrong_preregistered_digest_conflicts():
    files = {b"f": b"x"}
    blob, _digest = bundle_with_manifest(files)
    with pytest.raises(TarError) as exc:
        attest(blob, "0" * 64)
    assert exc.value.category == "manifest_digest_mismatch"


def test_attest_digest_checked_before_declaration_semantics():
    # Malformed declaration lines must never be inspected when the raw
    # manifest digest itself does not match the pre-registered value.
    files = {b"f": b"x"}
    blob = member_with_manifest(files, b"not-a-manifest")
    with pytest.raises(TarError) as exc:
        attest(blob, "0" * 64)
    assert exc.value.category == "manifest_digest_mismatch"


def test_attest_manifest_missing_member_entry():
    # Manifest omits an actual bundle member (extra member in bundle).
    files = {b"listed": b"a", b"unlisted": b"b"}
    partial = declaration({b"listed": b"a"})
    blob = member_with_manifest(files, partial)
    with pytest.raises(TarError) as exc:
        attest(blob, hashlib.sha256(partial).hexdigest())
    assert exc.value.category == "manifest_conflict"
    assert "unlisted" in exc.value.message


def test_attest_manifest_declares_nonexistent_member():
    files = {b"present": b"a"}
    overdeclared = declaration(
        {b"present": b"a", b"ghost": b"b"}
    )
    blob = member_with_manifest(files, overdeclared)
    with pytest.raises(TarError) as exc:
        attest(blob, hashlib.sha256(overdeclared).hexdigest())
    assert exc.value.category == "manifest_conflict"
    assert "ghost" in exc.value.message


def test_attest_manifest_size_mismatch_conflicts():
    files = {b"f": b"hello"}
    raw = (hashlib.sha256(b"hello").hexdigest().encode()
           + b"\t4\tf\n")  # actual size is 5
    blob = member_with_manifest(files, raw)
    with pytest.raises(TarError) as exc:
        attest(blob, hashlib.sha256(raw).hexdigest())
    assert exc.value.category == "manifest_conflict"
    assert "size" in exc.value.message


def test_attest_manifest_digest_mismatch_conflicts():
    files = {b"f": b"hello"}
    raw = b"0" * 64 + b"\t5\tf\n"
    blob = member_with_manifest(files, raw)
    with pytest.raises(TarError) as exc:
        attest(blob, hashlib.sha256(raw).hexdigest())
    assert exc.value.category == "manifest_conflict"
    assert "digest" in exc.value.message


def test_attest_bad_manifest_format_carries_line_number():
    files = {b"f": b"x"}
    bad = b"garbage line\n"
    blob = member_with_manifest(files, bad)
    with pytest.raises(TarError) as exc:
        attest(blob, hashlib.sha256(bad).hexdigest())
    assert exc.value.category == "bad_manifest"
    assert exc.value.line == 1


def test_attest_failure_raises_no_partial_result():
    files = {b"f": b"x"}
    blob = member_with_manifest(files, b"garbage\n")
    with pytest.raises(TarError):
        attest(blob, hashlib.sha256(b"garbage\n").hexdigest())
