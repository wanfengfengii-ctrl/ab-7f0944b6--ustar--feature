"""Interoperability with real-world USTAR producers (tarfile, GNU tar)."""

from __future__ import annotations

import hashlib
import io
import os
import shutil
import subprocess
import tarfile

import pytest

from app.tarutil import TarError, attest, parse_archive

from .tarbuilder import archive, file_member


def _tarfile_archive(files: dict[str, bytes], fmt) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=fmt) as tf:
        for name, content in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            info.mtime = 0
            tf.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def test_python_tarfile_ustar_accepted():
    files = {"a.txt": b"alpha", "d/b.txt": b"beta", "empty": b""}
    blob = _tarfile_archive(files, tarfile.USTAR_FORMAT)
    result = attest(blob)
    assert [e["path"] for e in result["entries"]] == ["a.txt", "d/b.txt", "empty"]
    first = result["entries"][0]
    assert first["sha256"] == hashlib.sha256(b"alpha").hexdigest()


def test_python_tarfile_pax_rejected():
    # A name exceeding the 100-byte USTAR limit forces a PAX 'x'
    # extended header (a path-aliasing channel); it must be rejected
    # rather than interpreted.
    long_name = "a" * 120 + ".txt"
    blob = _tarfile_archive({long_name: b"alpha"}, tarfile.PAX_FORMAT)
    with pytest.raises(TarError) as exc:
        parse_archive(blob)
    assert exc.value.category == "unsupported_type"


def test_python_tarfile_gnu_rejected():
    blob = _tarfile_archive({"a.txt": b"alpha"}, tarfile.GNU_FORMAT)
    # GNU magic differs (ustar ' ') or GNU meta headers appear.
    with pytest.raises(TarError):
        parse_archive(blob)


def test_tarfile_symlink_member_rejected():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        link = tarfile.TarInfo("lnk")
        link.type = tarfile.SYMTYPE
        link.linkname = "target"
        link.mtime = 0
        tf.addfile(link)
    with pytest.raises(TarError) as exc:
        parse_archive(buf.getvalue())
    assert exc.value.category == "unsupported_type"


def test_prefix_field_roundtrips_long_paths():
    # tarfile emits USTAR prefix splits for long-but-fittable names.
    name = "some/quite/deep/directory/tree/file.bin"
    blob = _tarfile_archive({name: b"payload"}, tarfile.USTAR_FORMAT)
    result = attest(blob)
    assert result["entries"][0]["path"] == name


@pytest.mark.skipif(shutil.which("tar") is None, reason="no system tar")
def test_gnu_tar_output_accepted(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "hello.txt").write_bytes(b"hello from tar\n")
    (src / "bin.dat").write_bytes(bytes(range(256)))
    out = tmp_path / "bundle.tar"
    # --format=ustar forces POSIX ustar; default blocking (10240 records,
    # i.e. zero padding after the two-block terminator).
    subprocess.run(
        ["tar", "--format=ustar", "-cf", str(out), "-C", str(src),
         "hello.txt", "bin.dat"],
        check=True,
    )
    raw = out.read_bytes()
    assert len(raw) % 10240 == 0  # record padding present
    result = attest(raw)
    assert [e["path"] for e in result["entries"]] == ["bin.dat", "hello.txt"]
    assert result["entries"][1]["sha256"] == hashlib.sha256(
        b"hello from tar\n"
    ).hexdigest()


@pytest.mark.skipif(shutil.which("tar") is None, reason="no system tar")
def test_gnu_tar_symlink_archive_rejected(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "real.txt").write_bytes(b"x")
    link = src / "lnk"
    try:
        os.symlink("real.txt", link)
    except (OSError, NotImplementedError):
        pytest.skip("symlink not supported")
    out = tmp_path / "bundle.tar"
    subprocess.run(
        ["tar", "--format=ustar", "-cf", str(out), "-C", str(src), "."],
        check=True,
    )
    # The archive also contains a "." directory entry (typeflag 5),
    # which is itself unsupported, so rejection is guaranteed either way.
    with pytest.raises(TarError) as exc:
        parse_archive(out.read_bytes())
    assert exc.value.category == "unsupported_type"
