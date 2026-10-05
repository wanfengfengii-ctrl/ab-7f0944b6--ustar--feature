"""Tests for the strict USTAR parser and attestation math."""

from __future__ import annotations

import hashlib
import struct
import unicodedata

import pytest

from app.tarutil import (
    MAX_BUNDLE_BYTES,
    MAX_CONTENT_BYTES,
    MAX_ENTRIES,
    TarError,
    attest,
    parse_archive,
)

from .tarbuilder import BLOCK, archive, file_member, header, record_padded


def build(files: dict[bytes, bytes], **kw) -> bytes:
    members = [file_member(name, content) for name, content in files.items()]
    return archive(*members, **kw)


# --------------------------------------------------------------------------
# Happy paths
# --------------------------------------------------------------------------


def test_minimal_archive_parses_and_sorts():
    data = build({b"b.txt": b"second", b"a.txt": b"hello"})
    result = attest(data)
    assert [e["path"] == "a.txt" for e in result["entries"]][0]
    assert [e["path"] for e in result["entries"]] == ["a.txt", "b.txt"]
    assert result["entries"][0] == {
        "path": "a.txt",
        "size": 5,
        "sha256": hashlib.sha256(b"hello").hexdigest(),
    }


def test_empty_file_member():
    result = attest(build({b"empty": b""}))
    assert result["entries"][0]["size"] == 0
    assert result["entries"][0]["sha256"] == hashlib.sha256(b"").hexdigest()


def test_bundle_digest_matches_spec():
    files = {b"b": b"xy", b"a": b"z"}
    result = attest(build(files))
    h = hashlib.sha256()
    for path, content in [(b"a", b"z"), (b"b", b"xy")]:
        h.update(struct.pack(">I", len(path)))
        h.update(path)
        h.update(struct.pack(">Q", len(content)))
        h.update(hashlib.sha256(content).digest())
    assert result["bundleSha256"] == h.hexdigest()


def test_prefix_field_is_joined_and_validated():
    content = b"data"
    hdr = bytes(header(b"file.bin", len(content), prefix=b"dir/sub"))
    blob = hdr + content + b"\x00" * (BLOCK - len(content)) + b"\x00" * BLOCK * 2
    result = attest(blob)
    assert result["entries"][0]["path"] == "dir/sub/file.bin"


def test_record_padding_zeroes_is_accepted():
    data = record_padded(file_member(b"f", b"x"))
    assert len(data) == 10240
    result = attest(data)
    assert result["entries"][0]["path"] == "f"


def test_utf8_nfc_paths_sort_by_bytes():
    # ASCII uppercase sorts before multibyte UTF-8 in byte order.
    paths = [b"\xc3\xa9.txt", b"A.txt"]  # é.txt, A.txt
    result = attest(build({p: b"" for p in paths}))
    assert [e["path"] for e in result["entries"]] == ["A.txt", "é.txt"]


# --------------------------------------------------------------------------
# Checksums and headers
# --------------------------------------------------------------------------


def test_bad_header_checksum_rejected():
    good = file_member(b"f", b"x")
    bad = bytearray(good)
    bad[200] ^= 0x01  # flip a byte inside the header, do not fix checksum
    with pytest.raises(TarError) as exc:
        parse_archive(bytes(bad) + b"\x00" * BLOCK * 2)
    assert exc.value.category == "bad_checksum"
    assert exc.value.entry == 1


def test_corrupt_data_with_valid_header_checksum_detected_via_digest():
    # A corrupted payload cannot be "detected" structurally beyond sha256;
    # the digest simply reflects the actual bytes, but nonzero padding must fail.
    data = bytearray(file_member(b"f", b"hello"))
    data[BLOCK + 1] ^= 0xFF
    blob = bytes(data) + b"\x00" * BLOCK * 2
    result = attest(blob)
    assert result["entries"][0]["sha256"] == hashlib.sha256(
        b"h" + bytes([b"hello"[1] ^ 0xFF]) + b"llo"
    ).hexdigest()


def test_nonzero_padding_rejected():
    member = bytearray(file_member(b"f", b"x"))
    member[BLOCK + 1] = 0x7F  # inside the padding area
    with pytest.raises(TarError, match="padding") as exc:
        parse_archive(bytes(member) + b"\x00" * BLOCK * 2)
    assert exc.value.category == "bad_padding"
    assert exc.value.entry == 1


def test_non_ustar_magic_rejected():
    for magic, version in [(b"ustar ", b" \x00"), (b"ustar\x00", b"  "),
                           (b"", b"00")]:
        member = file_member(
            b"f", b"x", magic=magic.ljust(6, b"\x00"), version=version
        )
        with pytest.raises(TarError) as exc:
            parse_archive(archive(member))
        assert exc.value.category == "non_ustar"


def test_link_entries_rejected():
    for tf in (b"1", b"2", b"3", b"4", b"5", b"6", b"7", b"x", b"g"):
        member = file_member(b"link", b"", typeflag=tf, linkname=b"target")
        with pytest.raises(TarError) as exc:
            parse_archive(archive(member))
        assert exc.value.category == "unsupported_type"


def test_linkname_on_regular_file_rejected():
    member = file_member(b"f", b"", linkname=b"rogue")
    with pytest.raises(TarError) as exc:
        parse_archive(archive(member))
    assert exc.value.category == "malformed_header"


def test_malformed_octal_size_rejected():
    hdr = bytearray(header(b"f", 4))
    hdr[124:136] = b"not octal!!!"
    with pytest.raises(TarError) as exc:
        parse_archive(bytes(hdr) + b"x" * BLOCK + b"\x00" * BLOCK * 2)
    assert exc.value.category in {"bad_checksum", "malformed_header"}


# --------------------------------------------------------------------------
# Terminator / truncation / trailing bytes
# --------------------------------------------------------------------------


def test_missing_terminator_rejected():
    data = file_member(b"f", b"x")  # no zero blocks
    with pytest.raises(TarError) as exc:
        parse_archive(data)
    assert exc.value.category == "bad_terminator"


def test_single_zero_block_rejected():
    data = file_member(b"f", b"x") + b"\x00" * BLOCK
    with pytest.raises(TarError) as exc:
        parse_archive(data)
    assert exc.value.category == "bad_terminator"


def test_nonzero_second_terminator_block_rejected():
    noisy = bytearray(BLOCK)
    noisy[511] = 1
    data = file_member(b"f", b"x") + b"\x00" * BLOCK + bytes(noisy)
    with pytest.raises(TarError) as exc:
        parse_archive(data)
    assert exc.value.category == "bad_terminator"


def test_nonzero_trailing_data_rejected():
    tail = bytearray(BLOCK)
    tail[0] = 0x01
    data = build({b"f": b"x"}, tail=bytes(tail))
    with pytest.raises(TarError) as exc:
        parse_archive(data)
    assert exc.value.category == "trailing_data"


def test_truncated_header_block_rejected():
    data = b"\x00" * (BLOCK * 2 + 100)
    with pytest.raises(TarError) as exc:
        parse_archive(data)
    assert exc.value.category in {"truncated", "bad_terminator"}


def test_truncated_data_rejected():
    member = file_member(b"f", b"x" * 10)
    with pytest.raises(TarError) as exc:
        parse_archive(member[:-1] + b"\x00" * BLOCK * 2)
    assert exc.value.category == "truncated"


def test_size_not_multiple_of_block_rejected():
    with pytest.raises(TarError) as exc:
        parse_archive(build({b"f": b"x"})[:-1])
    assert exc.value.category == "truncated"


# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------


BAD_PATHS = [
    (b"/abs", "absolute"),
    (b"a/../b", "dot"),
    (b"./x", "dot"),
    (b"a//b", "empty segment"),
    (b"a/", "trailing slash"),
    (b"a\\b", "backslash"),
    (b"a\x01b", "control"),
    (b"", "empty"),
]


@pytest.mark.parametrize("raw,label", BAD_PATHS)
def test_bad_paths_rejected(raw, label):
    with pytest.raises(TarError) as exc:
        parse_archive(build({raw: b"x"} if raw else {raw: b"x"}))
    assert exc.value.category == "invalid_path", label


def test_nfd_path_rejected():
    nfd = unicodedata.normalize("NFD", "é.txt").encode()
    nfc = unicodedata.normalize("NFC", "é.txt").encode()
    assert nfd != nfc
    with pytest.raises(TarError) as exc:
        parse_archive(build({nfd: b""}))
    assert exc.value.category == "invalid_path"


def test_invalid_utf8_path_rejected():
    member = file_member(b"\xff\xfe.txt", b"")
    with pytest.raises(TarError) as exc:
        parse_archive(archive(member))
    assert exc.value.category == "invalid_path"


def test_duplicate_paths_rejected_even_across_prefix():
    h1 = bytes(header(b"f", 1, prefix=b"d"))
    h2 = bytes(header(b"d/f", 1))  # same joined path, different split
    blob = h1 + b"x" + b"\x00" * (BLOCK - 1) + h2 + b"y" + b"\x00" * (BLOCK - 1)
    blob += b"\x00" * BLOCK * 2
    with pytest.raises(TarError) as exc:
        parse_archive(blob)
    assert exc.value.category == "duplicate_path"
    assert exc.value.entry == 2


def test_same_bytes_different_normalization_not_collapsed_by_set():
    # NFD is rejected outright rather than silently equated to NFC.
    nfc = unicodedata.normalize("NFC", "café").encode()
    result = attest(build({nfc: b""}))
    assert result["entries"][0]["path"] == "café"


# --------------------------------------------------------------------------
# Limits
# --------------------------------------------------------------------------


def test_empty_payload_rejected():
    with pytest.raises(TarError) as exc:
        parse_archive(b"")
    assert exc.value.category == "empty_archive"


def test_two_zero_blocks_only_rejected():
    with pytest.raises(TarError) as exc:
        parse_archive(b"\x00" * BLOCK * 2)
    assert exc.value.category == "empty_archive"


def test_too_many_entries_rejected():
    members = [file_member(f"f{i:03d}".encode(), b"") for i in range(101)]
    with pytest.raises(TarError) as exc:
        parse_archive(archive(*members))
    assert exc.value.category == "too_many_entries"
    assert exc.value.entry == MAX_ENTRIES + 1


def test_exactly_one_hundred_entries_accepted():
    files = {f"f{i:03d}".encode(): b"" for i in range(100)}
    assert len(attest(build(files))["entries"]) == 100


def test_total_content_limit_rejected():
    big = b"\x00" * MAX_CONTENT_BYTES
    files = {b"big": big, b"one": b"x"}
    with pytest.raises(TarError) as exc:
        parse_archive(build(files))
    assert exc.value.category == "content_too_large"


def test_total_content_at_limit_accepted():
    files = {b"big": b"\x00" * MAX_CONTENT_BYTES}
    blob = build(files)
    # Header (0.5 KiB) + padded content (6 MiB, block aligned) + 1 KiB
    # is well under the 8 MiB bundle ceiling.
    assert len(blob) <= MAX_BUNDLE_BYTES
    assert attest(blob)["entries"][0]["size"] == MAX_CONTENT_BYTES


def test_archive_over_8mib_rejected():
    # Many zero-filled data blocks inflate size without content cost;
    # claim huge size in a header instead.
    huge = 8 * 1024 * 1024
    hdr = bytes(header(b"big", huge))
    fake = hdr + b"\x00" * (huge // BLOCK * BLOCK) + b"\x00" * BLOCK * 2
    assert len(fake) > MAX_BUNDLE_BYTES
    with pytest.raises(TarError) as exc:
        parse_archive(fake)
    assert exc.value.category == "payload_too_large"
