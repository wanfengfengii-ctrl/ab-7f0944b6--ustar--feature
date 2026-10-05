"""Helpers that fabricate USTAR archives byte-by-byte for testing.

Unlike :mod:`tarfile`, these builders let a test corrupt exactly one
invariant (checksum, padding, terminator, ...) while keeping the rest
of the archive well formed.
"""

from __future__ import annotations

import struct

BLOCK = 512


def _octal(value: int, width: int) -> bytes:
    return f"{value:0{width - 1}o}".encode().ljust(width, b"\x00")[:width]


def header(
    name: bytes,
    size: int,
    *,
    typeflag: bytes = b"0",
    prefix: bytes = b"",
    magic: bytes = b"ustar\x00",
    version: bytes = b"00",
    linkname: bytes = b"",
    uname: bytes = b"root",
    gname: bytes = b"root",
    mode: int = 0o644,
    mtime: int = 0,
    checksum: bytes | None = None,
) -> bytearray:
    block = bytearray(BLOCK)

    def put(span, value: bytes) -> None:
        start, end = span
        block[start:start + len(value)] = value[: end - start]

    put((0, 100), name)
    put((100, 108), _octal(mode, 8))
    put((108, 116), _octal(0, 8))       # uid
    put((116, 124), _octal(0, 8))       # gid
    put((124, 136), _octal(size, 12))
    put((136, 148), _octal(mtime, 12))
    # checksum placeholder: eight spaces
    block[148:156] = b" " * 8
    block[156] = typeflag[0] if isinstance(typeflag, (bytes, bytearray)) else typeflag
    put((157, 257), linkname)
    put((257, 263), magic)
    put((263, 265), version)
    put((265, 297), uname)
    put((297, 329), gname)
    put((329, 337), _octal(0, 8))       # devmajor
    put((337, 345), _octal(0, 8))       # devminor
    put((345, 500), prefix)

    if checksum is None:
        total = sum(block)
        checksum = f"{total:06o}".encode() + b"\x00 "
    put((148, 156), checksum)
    return block


def file_member(name, content: bytes, *, typeflag=b"0", **kwargs) -> bytes:
    hdr = bytes(header(name, len(content), typeflag=typeflag, **kwargs))
    padding = b"\x00" * ((-len(content)) % BLOCK)
    return hdr + content + padding


def archive(*members: bytes, terminator: bytes = b"\x00" * BLOCK * 2,
            tail: bytes = b"") -> bytes:
    return b"".join(members) + terminator + tail


def record_padded(*members: bytes, record: int = 10240) -> bytes:
    """Archive padded to a *record* boundary, as GNU tar writes by default."""
    body = b"".join(members) + b"\x00" * BLOCK * 2
    return body + b"\x00" * ((-len(body)) % record)
