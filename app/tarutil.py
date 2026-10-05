"""Strict USTAR parser and bundle attestation.

Only uncompressed POSIX.1-1988 (``ustar\\0`` / ``00``) archives made up
exclusively of regular files are accepted.  Any deviation -- truncated
blocks, bad header checksums, non-standard headers, links, non-zero
padding, a non-canonical terminator, trailing non-zero bytes or
ambiguous paths -- raises :class:`TarError` with a stable, locatable
``category``.
"""

from __future__ import annotations

import hashlib
import re
import struct
import unicodedata
from dataclasses import dataclass

BLOCK_SIZE = 512
MAX_BUNDLE_BYTES = 8 * 1024 * 1024
MAX_CONTENT_BYTES = 6 * 1024 * 1024
MAX_ENTRIES = 100
MIN_ENTRIES = 1

# Header field offsets (POSIX ustar).
NAME = (0, 100)
MODE = (100, 108)
UID = (108, 116)
GID = (116, 124)
SIZE = (124, 136)
MTIME = (136, 148)
CHECKSUM = (148, 156)
TYPEFLAG = 156
LINKNAME = (157, 257)
MAGIC = (257, 263)
VERSION = (263, 265)
UNAME = (265, 297)
GNAME = (297, 329)
DEVMAJOR = (329, 337)
DEVMINOR = (337, 345)
PREFIX = (345, 500)

_OCTAL_DIGITS = re.compile(rb"[0-7]+")
_USTAR_MAGIC = b"ustar\x00"
_USTAR_VERSION = b"00"


class TarError(Exception):
    """An error whose ``category`` pinpoints what went wrong.

    ``entry`` is the 1-based ordinal of the header being parsed (when
    known) so a rejected submission can be traced to a specific member.
    """

    def __init__(self, category: str, message: str, entry: int | None = None):
        super().__init__(message)
        self.category = category
        self.message = message
        self.entry = entry

    def to_dict(self) -> dict:
        body = {"category": self.category, "message": self.message}
        if self.entry is not None:
            body["entry"] = self.entry
        return body


@dataclass(frozen=True)
class Entry:
    path: bytes  # NFC UTF-8 bytes
    size: int
    digest: bytes  # raw SHA-256 of the file content


# ---------------------------------------------------------------------------
# Low level field helpers
# ---------------------------------------------------------------------------


def _fixed_text(block: bytes, span: tuple[int, int], what: str,
                entry: int) -> bytes:
    """Return a NUL-terminated fixed field, rejecting trailing garbage."""
    start, end = span
    field = block[start:end]
    nul = field.find(b"\x00")
    if nul < 0:
        return field  # a field that fills its whole width has no terminator
    value, tail = field[:nul], field[nul + 1:]
    if tail and tail != b"\x00" * len(tail):
        raise TarError(
            "malformed_header", f"{what} field has trailing non-NUL bytes", entry
        )
    return value


def _octal_field(block: bytes, span: tuple[int, int], what: str,
                 entry: int) -> int:
    field = bytes(block[span[0]:span[1]])
    trimmed = field.strip(b"\x00 ")
    if not trimmed:
        return 0
    if not _OCTAL_DIGITS.fullmatch(trimmed):
        raise TarError("malformed_header", f"malformed octal field: {what}", entry)
    return int(trimmed, 8)


def _header_checksum(block: bytes) -> int:
    """Standard USTAR checksum: the checksum field itself counts as spaces."""
    return sum(block[:148]) + sum(b"        ") + sum(block[156:])


def _stored_checksum(block: bytes, entry: int) -> int:
    field = bytes(block[CHECKSUM[0]:CHECKSUM[1]])
    trimmed = field.strip(b"\x00 ")
    if not trimmed:
        return 0
    if not _OCTAL_DIGITS.fullmatch(trimmed):
        raise TarError("bad_checksum", "header checksum is not octal", entry)
    return int(trimmed, 8)


# ---------------------------------------------------------------------------
# Path validation
# ---------------------------------------------------------------------------


def validate_path(raw: bytes, entry: int) -> str:
    """Validate a UTF-8 NFC, slash-separated relative path."""
    try:
        path = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise TarError("invalid_path", "path is not valid UTF-8", entry)

    if unicodedata.normalize("NFC", path) != path:
        raise TarError("invalid_path", "path is not Unicode NFC", entry)

    if not path:
        raise TarError("invalid_path", "empty path", entry)
    if path.startswith("/"):
        raise TarError("invalid_path", "absolute path is not allowed", entry)
    if "\\" in path:
        raise TarError("invalid_path", "backslash is not allowed in path", entry)

    for segment in path.split("/"):
        if segment == "":
            raise TarError("invalid_path", "empty path segment", entry)
        if segment in (".", ".."):
            raise TarError("invalid_path", "dot segment is not allowed", entry)
        for ch in segment:
            if unicodedata.category(ch) == "Cc":
                raise TarError("invalid_path", "control character in path", entry)
    return path


# ---------------------------------------------------------------------------
# Archive parsing
# ---------------------------------------------------------------------------


def parse_archive(data: bytes) -> list[Entry]:
    if len(data) > MAX_BUNDLE_BYTES:
        raise TarError("payload_too_large", "archive exceeds 8 MiB")
    if len(data) == 0:
        raise TarError("empty_archive", "archive contains no entries")
    if len(data) % BLOCK_SIZE != 0:
        raise TarError("truncated", "archive size is not a multiple of 512 bytes")

    entries: list[Entry] = []
    seen: set[bytes] = set()
    total_content = 0
    pos = 0
    zero_block = b"\x00" * BLOCK_SIZE

    while pos < len(data):
        block = data[pos:pos + BLOCK_SIZE]
        if len(block) < BLOCK_SIZE:
            raise TarError("truncated", "truncated header block")

        if block == zero_block:
            # Canonical end-of-archive marker: exactly two zero blocks.
            second = data[pos + BLOCK_SIZE:pos + 2 * BLOCK_SIZE]
            if len(second) < BLOCK_SIZE:
                raise TarError(
                    "bad_terminator",
                    "end-of-archive marker is missing its second zero block",
                )
            if second != zero_block:
                raise TarError(
                    "bad_terminator",
                    "second end-of-archive block is not zero",
                )
            tail = data[pos + 2 * BLOCK_SIZE:]
            # Additional all-zero blocks are permitted record padding;
            # anything non-zero after the marker is rejected.
            if tail and tail != b"\x00" * len(tail):
                raise TarError(
                    "trailing_data",
                    "non-zero data follows the end-of-archive marker",
                )
            break

        entry_no = len(entries) + 1
        if entry_no > MAX_ENTRIES:
            raise TarError(
                "too_many_entries",
                f"archive holds more than {MAX_ENTRIES} files",
                entry_no,
            )

        if _stored_checksum(block, entry_no) != _header_checksum(block):
            raise TarError("bad_checksum", "header checksum mismatch", entry_no)

        if bytes(block[MAGIC[0]:MAGIC[1]]) != _USTAR_MAGIC or bytes(
            block[VERSION[0]:VERSION[1]]
        ) != _USTAR_VERSION:
            raise TarError(
                "non_ustar",
                "header magic/version is not POSIX ustar (ustar\\0, version 00)",
                entry_no,
            )

        typeflag = block[TYPEFLAG]
        if typeflag not in (ord("0"), 0):
            kind = chr(typeflag) if 32 <= typeflag < 127 else f"0x{typeflag:02x}"
            raise TarError(
                "unsupported_type",
                f"unsupported entry type {kind!r}; only regular files are allowed",
                entry_no,
            )

        # Shape-check every standard numeric field.
        size = _octal_field(block, SIZE, "size", entry_no)
        numeric = {}
        for span, what in (
            (MODE, "mode"),
            (UID, "uid"),
            (GID, "gid"),
            (MTIME, "mtime"),
            (DEVMAJOR, "devmajor"),
            (DEVMINOR, "devminor"),
        ):
            numeric[what] = _octal_field(block, span, what, entry_no)

        # Device numbers are meaningful only for char/block devices; a
        # regular-file header carrying them is non-standard.
        if numeric["devmajor"] != 0 or numeric["devminor"] != 0:
            raise TarError(
                "malformed_header",
                "device major/minor must be zero on a regular-file header",
                entry_no,
            )

        # Text fields must be cleanly NUL-terminated.
        for span, what in (
            (UNAME, "uname"),
            (GNAME, "gname"),
        ):
            _fixed_text(block, span, what, entry_no)

        if bytes(block[LINKNAME[0]:LINKNAME[1]]).rstrip(b"\x00"):
            raise TarError(
                "malformed_header",
                "regular file header carries a link name",
                entry_no,
            )

        name = _fixed_text(block, NAME, "name", entry_no)
        prefix = _fixed_text(block, PREFIX, "prefix", entry_no)
        raw_path = prefix + b"/" + name if prefix else name
        path_text = validate_path(raw_path, entry_no)

        if raw_path in seen:
            raise TarError("duplicate_path", f"duplicate path: {path_text}", entry_no)
        seen.add(raw_path)

        data_blocks = (size + BLOCK_SIZE - 1) // BLOCK_SIZE
        data_start = pos + BLOCK_SIZE
        data_end = data_start + size
        pad_end = data_start + data_blocks * BLOCK_SIZE
        if pad_end > len(data):
            raise TarError("truncated", "entry data is truncated", entry_no)
        content = data[data_start:data_end]
        padding = data[data_end:pad_end]
        if padding and padding != b"\x00" * len(padding):
            raise TarError("bad_padding", "non-zero padding after entry data", entry_no)

        total_content += size
        if total_content > MAX_CONTENT_BYTES:
            raise TarError(
                "content_too_large",
                "sum of file contents exceeds 6 MiB",
                entry_no,
            )

        entries.append(
            Entry(path=raw_path, size=size, digest=hashlib.sha256(content).digest())
        )
        pos = pad_end
    else:  # pragma: no cover - loop always ends via break or raise
        raise TarError("bad_terminator", "missing end-of-archive marker")

    if len(entries) < MIN_ENTRIES:
        raise TarError("empty_archive", "archive contains no entries")
    return entries


# ---------------------------------------------------------------------------
# Attestation
# ---------------------------------------------------------------------------


def attest(data: bytes) -> dict:
    """Parse *data* and return the bytewise-sorted manifest and bundle digest."""
    entries = parse_archive(data)
    ordered = sorted(entries, key=lambda e: e.path)

    bundle_hash = hashlib.sha256()
    manifest = []
    for entry in ordered:
        bundle_hash.update(struct.pack(">I", len(entry.path)))
        bundle_hash.update(entry.path)
        bundle_hash.update(struct.pack(">Q", entry.size))
        bundle_hash.update(entry.digest)
        manifest.append(
            {
                "path": entry.path.decode("utf-8"),
                "size": entry.size,
                "sha256": entry.digest.hex(),
            }
        )

    return {
        "bundleSha256": bundle_hash.hexdigest(),
        "entries": manifest,
    }
