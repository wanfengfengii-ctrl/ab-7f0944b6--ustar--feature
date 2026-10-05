"""Tests for the BUNDLE.MANIFEST declaration and its cross-checks."""

from __future__ import annotations

import hashlib

import pytest

from app.tarutil import (
    MANIFEST_PATH,
    ManifestError,
    attest,
    build_manifest_bytes,
    parse_manifest,
    verify_manifest,
)

from .tarbuilder import archive, file_member
from tests.manifest_helpers import bundle_with_manifest, manifest_text


# --------------------------------------------------------------------------
# Happy paths
# --------------------------------------------------------------------------


def test_valid_declaration_passes_and_reports_manifest_digest():
    files = {b"dir/a.bin": b"hello", b"readme.txt": b"world\n"}
    blob, declared = bundle_with_manifest(files)
    result = attest(blob, manifest_sha256=declared)
    assert result["manifestSha256"] == declared
    # The declaration itself is listed as an ordinary member.
    assert [e["path"] for e in result["entries"]] == [
        "BUNDLE.MANIFEST", "dir/a.bin", "readme.txt",
    ]


def test_header_omitted_keeps_legacy_contract():
    files = {b"a": b"x"}
    blob, _ = bundle_with_manifest(files)
    result = attest(blob)  # no header value -> plain USTAR attestation
    assert "manifestSha256" not in result
    assert [e["path"] for e in result["entries"]] == [
        "BUNDLE.MANIFEST", "a",
    ]


def test_manifest_only_bundle_with_empty_declaration_passes():
    text = b""
    blob, declared = bundle_with_manifest({}, text=text)
    result = attest(blob, manifest_sha256=declared)
    assert result["manifestSha256"] == hashlib.sha256(b"").hexdigest()
    assert [e["path"] for e in result["entries"]] == ["BUNDLE.MANIFEST"]


def test_result_digest_is_of_raw_archive_bytes_not_reconstruction():
    # Build a valid bundle, then flip a byte inside the manifest content
    # and resend with the *original* header digest: anything that
    # re-serialised the declaration would miss this.
    files = {b"a": b"x"}
    blob, declared = bundle_with_manifest(files)
    damaged = bytearray(blob)
    # Layout: a header (0), a data (512), manifest header (1024),
    # manifest content starts at 1536.
    damaged[1536] ^= 0x01  # first byte of the manifest content
    with pytest.raises(ManifestError) as exc:
        attest(bytes(damaged), manifest_sha256=declared)
    assert exc.value.category == "manifest_digest_mismatch"


def test_build_manifest_bytes_is_canonical():
    from app.tarutil import Entry

    entries = [
        Entry(path=b"a", size=2, digest=hashlib.sha256(b"xy").digest(),
              content_offset=0),
    ]
    line = hashlib.sha256(b"xy").hexdigest().encode() + b"\t2\ta\n"
    assert build_manifest_bytes(entries) == line


# --------------------------------------------------------------------------
# Pre-registration digest
# --------------------------------------------------------------------------


def test_declared_digest_mismatch_rejected():
    blob, _ = bundle_with_manifest({b"a": b"x"})
    wrong = "0" * 64
    with pytest.raises(ManifestError) as exc:
        attest(blob, manifest_sha256=wrong)
    assert exc.value.category == "manifest_digest_mismatch"


# --------------------------------------------------------------------------
# Item-by-item conflicts
# --------------------------------------------------------------------------


def test_item_digest_mismatch_reported_with_path():
    files = {b"a": b"actual"}
    text = manifest_text(
        {b"a": (hashlib.sha256(b"declared").digest(), len(b"actual"))}
    )
    blob, declared = bundle_with_manifest(files, text=text)
    with pytest.raises(ManifestError) as exc:
        attest(blob, manifest_sha256=declared)
    assert exc.value.category == "manifest_digest_item_mismatch"
    assert exc.value.path == "a"


def test_size_mismatch_reported_with_path():
    files = {b"a": b"actual"}
    digest = hashlib.sha256(b"actual").digest()
    text = manifest_text({b"a": (digest, 99)})
    blob, declared = bundle_with_manifest(files, text=text)
    with pytest.raises(ManifestError) as exc:
        attest(blob, manifest_sha256=declared)
    assert exc.value.category == "manifest_size_mismatch"
    assert exc.value.path == "a"


def test_undeclared_member_reported_as_missing():
    # The archive holds an extra file the declaration never mentions.
    text = manifest_text({b"a": b"x"})
    blob = archive(
        file_member(b"a", b"x"),
        file_member(b"b", b"y"),
        file_member(MANIFEST_PATH, text),
    )
    declared = hashlib.sha256(text).hexdigest()
    with pytest.raises(ManifestError) as exc:
        attest(blob, manifest_sha256=declared)
    assert exc.value.category == "manifest_missing"
    assert exc.value.path == "b"


def test_extra_declaration_reported_as_extra():
    # The declaration mentions a path the archive does not contain.
    text = manifest_text({b"a": b"x", b"ghost": b"?"})
    blob = archive(
        file_member(b"a", b"x"),
        file_member(MANIFEST_PATH, text),
    )
    declared = hashlib.sha256(text).hexdigest()
    with pytest.raises(ManifestError) as exc:
        attest(blob, manifest_sha256=declared)
    assert exc.value.category == "manifest_extra"
    assert exc.value.path == "ghost"


def test_manifest_declaring_itself_rejected():
    # "BUNDLE.MANIFEST" (0x42…) sorts before "a" (0x61…), so the
    # self-referential row must come first to pass ordering checks.
    a_line = (hashlib.sha256(b"x").hexdigest().encode() + b"\t1\ta\n")
    text = b"0" * 64 + b"\t0\t" + MANIFEST_PATH + b"\n" + a_line
    blob = archive(
        file_member(MANIFEST_PATH, text),
        file_member(b"a", b"x"),
    )
    declared = hashlib.sha256(text).hexdigest()
    with pytest.raises(ManifestError) as exc:
        attest(blob, manifest_sha256=declared)
    assert exc.value.category == "manifest_extra"
    assert exc.value.path == "BUNDLE.MANIFEST"


def test_bundle_without_manifest_member_rejected_when_header_present():
    blob = archive(file_member(b"a", b"x"))
    with pytest.raises(ManifestError) as exc:
        attest(blob, manifest_sha256="0" * 64)
    assert exc.value.category == "manifest_missing"


def test_nested_manifest_path_does_not_count():
    # Only an exact top-level BUNDLE.MANIFEST satisfies the requirement.
    text = manifest_text({b"a": b"x"})
    blob = archive(
        file_member(b"a", b"x"),
        file_member(b"config/BUNDLE.MANIFEST", text),
    )
    declared = hashlib.sha256(text).hexdigest()
    with pytest.raises(ManifestError) as exc:
        attest(blob, manifest_sha256=declared)
    assert exc.value.category == "manifest_missing"


# --------------------------------------------------------------------------
# Declaration text format (line numbers)
# --------------------------------------------------------------------------


BAD_LINES = [
    (b"\t0\ta\n", "empty digest"),
    (b"z" * 64 + b"\t0\ta\n", "non-hex digest"),
    (b"A" * 64 + b"\t0\ta\n", "uppercase digest"),
    (b"0" * 63 + b"\t0\ta\n", "short digest"),
    (b"0" * 64 + b"  0\ta\n", "spaces around size"),
    (b"0" * 64 + b"\t00\ta\n", "leading-zero size"),
    (b"0" * 64 + b"\t-1\ta\n", "negative size"),
    (b"0" * 64 + b"\t+1\ta\n", "plus size"),
    (b"0" * 64 + b"\t0 a\n", "missing tab"),
    (b"0" * 64 + b"\t0\ta", "missing trailing newline"),
    (b"0" * 64 + b"\t0\ta\r\n", "CRLF ending"),
    (b"0" * 64 + b"\t0\ta\tx\n", "extra tab field"),
]


@pytest.mark.parametrize("bad,label", BAD_LINES)
def test_malformed_single_line_reports_line_1(bad, label):
    with pytest.raises(ManifestError) as exc:
        parse_manifest(bad)
    assert exc.value.category == "malformed_manifest", label
    assert exc.value.line == 1, label


def test_blank_line_after_good_line_reports_line_2():
    good = hashlib.sha256(b"x").hexdigest().encode() + b"\t1\ta\n"
    with pytest.raises(ManifestError) as exc:
        parse_manifest(good + b"\n")
    assert exc.value.category == "malformed_manifest"
    assert exc.value.line == 2


def test_non_ascii_byte_reports_its_line():
    good = manifest_text({b"a": b"x"})
    # A multibyte UTF-8 path would be fine, but a raw 0xFF byte makes
    # the second line non-ASCII.
    bad = good + b"0" * 64 + b"\t0\t\xff\n"
    with pytest.raises(ManifestError) as exc:
        parse_manifest(bad)
    assert exc.value.category == "malformed_manifest"
    assert exc.value.line == 2


def test_error_line_counts_from_one_on_second_line():
    good = manifest_text({b"a": b"x"})
    bad = good + b"garbage line\n"
    with pytest.raises(ManifestError) as exc:
        parse_manifest(bad)
    assert exc.value.category == "malformed_manifest"
    assert exc.value.line == 2


def test_unsorted_paths_rejected_with_line():
    a = hashlib.sha256(b"x").hexdigest().encode()
    text = a + b"\t1\tb\n" + a + b"\t1\ta\n"
    with pytest.raises(ManifestError) as exc:
        parse_manifest(text)
    assert exc.value.category == "manifest_unsorted"
    assert exc.value.line == 2


def test_duplicate_rows_rejected_with_line():
    a = hashlib.sha256(b"x").hexdigest().encode()
    text = a + b"\t1\ta\n" + a + b"\t1\ta\n"
    with pytest.raises(ManifestError) as exc:
        parse_manifest(text)
    assert exc.value.category == "manifest_duplicate"
    assert exc.value.line == 2


def test_sorted_by_utf8_bytes_not_codepoints():
    # The declaration file is ASCII, so ordering is checked on ASCII
    # paths; "A" (0x41) must precede "a" (0x61).
    text = manifest_text({b"A.txt": b"", b"a.txt": b""})
    assert parse_manifest(text)  # no raise
    zero = hashlib.sha256(b"").hexdigest().encode()
    rev = zero + b"\t0\ta.txt\n" + zero + b"\t0\tA.txt\n"
    with pytest.raises(ManifestError) as exc:
        parse_manifest(rev)
    assert exc.value.category == "manifest_unsorted"


def test_verify_manifest_requires_exactly_the_members():
    from app.tarutil import Entry

    e = Entry(path=b"a", size=1, digest=hashlib.sha256(b"x").digest())
    with pytest.raises(ManifestError) as exc:
        verify_manifest([e], b"")
    assert exc.value.category == "manifest_missing"
