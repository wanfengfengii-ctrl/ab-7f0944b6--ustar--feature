"""Helpers for building bundles that carry a BUNDLE.MANIFEST member."""

from __future__ import annotations

import hashlib

from app.tarutil import MANIFEST_PATH

from .tarbuilder import archive, file_member


def manifest_text(spec: dict) -> bytes:
    """Render canonical declaration lines for *spec*.

    Each value is either the file's content bytes, or an explicit
    ``(raw_digest, size)`` pair for producing conflicting declarations.
    """
    lines = []
    for path in sorted(spec):
        value = spec[path]
        if isinstance(value, tuple):
            digest, size = value
        else:
            digest = hashlib.sha256(value).digest()
            size = len(value)
        lines.append(
            digest.hex().encode("ascii") + b"\t"
            + str(size).encode("ascii") + b"\t" + path + b"\n"
        )
    return b"".join(lines)


def bundle_with_manifest(files: dict, *, text: bytes | None = None,
                         extra_members: list[bytes] | None = None):
    """Return ``(archive_bytes, manifest_sha256_hex)``.

    *files* maps member paths to their actual content; the declaration
    is derived from them unless *text* overrides it.  Extra pre-built
    *extra_members* (e.g. a second manifest copy) can be appended.
    """
    if text is None:
        text = manifest_text(files)
    parts = [file_member(name, content)
             for name, content in sorted(files.items())]
    parts.append(file_member(MANIFEST_PATH, text))
    if extra_members:
        parts.extend(extra_members)
    return archive(*parts), hashlib.sha256(text).hexdigest()
