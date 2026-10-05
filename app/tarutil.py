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

# The in-bundle declaration file.  When X-Bundle-Manifest-Sha256 is sent
# the archive must contain exactly one member under this path.
MANIFEST_PATH = b"BUNDLE.MANIFEST"

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


class ManifestError(Exception):
    """A BUNDLE.MANIFEST declaration that cannot be parsed or does not
    match the archive.

    ``line`` is the 1-based line number for format errors; ``path`` is
    the offending member path (decoded text) for conflict errors.
    """

    def __init__(self, category: str, message: str,
                 line: int | None = None, path: str | None = None):
        super().__init__(message)
        self.category = category
        self.message = message
        self.line = line
        self.path = path

    def to_dict(self) -> dict:
        body = {"category": self.category, "message": self.message}
        if self.line is not None:
            body["line"] = self.line
        if self.path is not None:
            body["path"] = self.path
        return body


@dataclass(frozen=True)
class Entry:
    path: bytes  # NFC UTF-8 bytes
    size: int
    digest: bytes  # raw SHA-256 of the file content
    content_offset: int = -1  # byte offset of the content inside the archive


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
            Entry(path=raw_path, size=size,
                  digest=hashlib.sha256(content).digest(),
                  content_offset=data_start)
        )
        pos = pad_end
    else:  # pragma: no cover - loop always ends via break or raise
        raise TarError("bad_terminator", "missing end-of-archive marker")

    if len(entries) < MIN_ENTRIES:
        raise TarError("empty_archive", "archive contains no entries")
    return entries


# ---------------------------------------------------------------------------
# Manifest declaration
# ---------------------------------------------------------------------------

# One declared member: "<sha256 hex>\t<decimal size>\t<path>\n".
# Digests are lowercase hex (64 chars), sizes canonical decimal (no
# sign/spaces/leading zeroes, "0" allowed), paths are exactly the
# NFC UTF-8 bytes accepted by validate_path (no tab, LF or CR in them).
_MANIFEST_LINE = re.compile(rb"([0-9a-f]{64})\t(0|[1-9][0-9]*)\t([^\t\n\r]*)\n")

_MANIFEST_TEXT_LIMIT = MAX_BUNDLE_BYTES


def build_manifest_bytes(entries: list[Entry]) -> bytes:
    """Serialise *entries* (already UTF-8 byte sorted, manifest excluded)
    into the canonical declaration text."""
    out = bytearray()
    for entry in entries:
        out.extend(entry.digest.hex().encode("ascii"))
        out.append(0x09)
        out.extend(str(entry.size).encode("ascii"))
        out.append(0x09)
        out.extend(entry.path)
        out.append(0x0A)
    return bytes(out)


def parse_manifest(data: bytes) -> list[tuple[bytes, int, bytes]]:
    """Parse declaration text into ``(path, size, raw_digest)`` rows.

    Raises :class:`ManifestError` with ``line`` set on any format
    violation, including non-ASCII bytes, paths that are not valid
    NFC UTF-8, and missing strict UTF-8 byte ordering.
    """
    if len(data) > _MANIFEST_TEXT_LIMIT:
        raise ManifestError("malformed_manifest", "manifest is too large")
    try:
        data.decode("ascii")
    except UnicodeDecodeError:
        # Pinpoint the first non-ASCII byte's line for the caller.
        line = data.count(b"\n", 0, _first_non_ascii(data)) + 1
        raise ManifestError(
            "malformed_manifest", "manifest is not ASCII text", line
        )
    # A zero-length declaration is legal: it covers no members.
    if data == b"":
        return []
    if not data.endswith(b"\n"):
        raise ManifestError(
            "malformed_manifest",
            "manifest must end with a newline",
            data.count(b"\n") + 1,
        )

    rows: list[tuple[bytes, int, bytes]] = []
    prev_path: bytes | None = None
    # split(b"\n") of a newline-terminated blob yields a trailing "" that
    # we drop; every other piece is exactly one declaration line.
    for line_no, line in enumerate(data.split(b"\n")[:-1], start=1):
        match = _MANIFEST_LINE.fullmatch(line + b"\n")
        if not match:
            raise ManifestError(
                "malformed_manifest",
                "expected '<sha256>\t<size>\t<path>' with trailing newline",
                line_no,
            )
        digest_hex, size_text, path = match.groups()
        if not path:
            raise ManifestError(
                "malformed_manifest", "empty path", line_no
            )
        # Declared paths must satisfy the same rules as member paths.
        try:
            validate_path(path, line_no)
        except TarError as exc:
            raise ManifestError(
                "malformed_manifest", exc.message, line_no
            ) from exc
        if prev_path is not None and not (prev_path < path):
            if prev_path == path:
                raise ManifestError(
                    "manifest_duplicate", "duplicate path in manifest", line_no
                )
            raise ManifestError(
                "manifest_unsorted",
                "paths are not sorted by UTF-8 byte order",
                line_no,
            )
        prev_path = path
        rows.append((path, int(size_text), bytes.fromhex(digest_hex.decode())))
    return rows


def _first_non_ascii(data: bytes) -> int:
    for index, byte in enumerate(data):
        if byte > 127:
            return index
    return len(data)


def verify_manifest(entries: list[Entry], manifest_content: bytes,
                    declared_digest: str | None = None) -> str:
    """Cross-check the in-bundle declaration against parsed members.

    *entries* must include the BUNDLE.MANIFEST member.  The manifest's
    own raw-byte digest is checked first (against *declared_digest*, the
    value of X-Bundle-Manifest-Sha256), then every row is compared
    against archive members and vice versa.  Returns the lowercase hex
    digest of the manifest bytes.
    """
    actual_digest = hashlib.sha256(manifest_content).hexdigest()
    if declared_digest is not None and actual_digest != declared_digest:
        raise ManifestError(
            "manifest_digest_mismatch",
            "manifest content digest does not match X-Bundle-Manifest-Sha256",
        )

    rows = parse_manifest(manifest_content)

    by_path: dict[bytes, Entry] = {}
    manifest_members = 0
    for entry in entries:
        if entry.path == MANIFEST_PATH:
            manifest_members += 1
            continue
        by_path[entry.path] = entry

    if manifest_members != 1:
        # The header gate requires exactly one; a duplicate path cannot
        # reach here (parse_archive rejects it), so this is "missing".
        raise ManifestError(
            "manifest_missing",
            "bundle must contain exactly one BUNDLE.MANIFEST",
        )

    row_paths = set()
    for path, size, digest in rows:
        if path == MANIFEST_PATH:
            raise ManifestError(
                "manifest_extra",
                "manifest must not declare itself",
                path=MANIFEST_PATH.decode(),
            )
        row_paths.add(path)
        entry = by_path.get(path)
        if entry is None:
            raise ManifestError(
                "manifest_extra",
                "declared path is not a bundle member",
                path=path.decode("utf-8", errors="surrogateescape"),
            )
        if entry.size != size:
            raise ManifestError(
                "manifest_size_mismatch",
                f"declared size {size} does not match member size {entry.size}",
                path=path.decode("utf-8", errors="surrogateescape"),
            )
        if entry.digest != digest:
            raise ManifestError(
                "manifest_digest_item_mismatch",
                "declared sha256 does not match member content",
                path=path.decode("utf-8", errors="surrogateescape"),
            )

    member_paths = set(by_path)
    if row_paths < member_paths:
        missing = next(iter(member_paths - row_paths))
        raise ManifestError(
            "manifest_missing",
            "bundle member is not covered by the manifest",
            path=missing.decode("utf-8", errors="surrogateescape"),
        )
    if row_paths > member_paths:  # pragma: no cover - handled row by row
        extra = next(iter(row_paths - member_paths))
        raise ManifestError(
            "manifest_extra",
            "declared path is not a bundle member",
            path=extra.decode("utf-8", errors="surrogateescape"),
        )
    return actual_digest


# ---------------------------------------------------------------------------
# Attestation
# ---------------------------------------------------------------------------


def attest(data: bytes, manifest_sha256: str | None = None) -> dict:
    """Parse *data* and return the bytewise-sorted manifest and bundle digest.

    When *manifest_sha256* is given, the bundle must contain exactly one
    ``BUNDLE.MANIFEST`` member whose raw bytes hash to that value and
    whose declarations match every other member exactly.  The success
    document then additionally carries ``manifestSha256``.
    """
    entries = parse_archive(data)
    ordered = sorted(entries, key=lambda e: e.path)

    manifest_digest: str | None = None
    if manifest_sha256 is not None:
        manifest_entries = [e for e in ordered if e.path == MANIFEST_PATH]
        if len(manifest_entries) != 1:
            raise ManifestError(
                "manifest_missing",
                "bundle must contain exactly one BUNDLE.MANIFEST",
            )
        # Read the declaration's raw bytes from the archive so it is
        # verified byte-for-byte, not reconstructed from parsed members.
        manifest_entry = manifest_entries[0]
        start = manifest_entry.content_offset
        manifest_content = data[start:start + manifest_entry.size]
        manifest_digest = verify_manifest(
            ordered, manifest_content, manifest_sha256
        )

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

    result = {
        "bundleSha256": bundle_hash.hexdigest(),
        "entries": manifest,
    }
    if manifest_digest is not None:
        result["manifestSha256"] = manifest_digest
    return result
