from __future__ import annotations

import importlib
import io
import zipfile

from pystandalone.compiler import NoCompiler, PycCompiler
from pystandalone.packer import Packer, mkzip, zinfo, zwrite


def test_pack_compiles_py_to_pyc() -> None:
    """Test that .py files are compiled to .pyc in the output zip."""
    compiler = PycCompiler(importlib.util.MAGIC_NUMBER)
    packer = Packer(compiler)

    content = [("run.py", "x = 1"), ("lib/util.py", "y = 2")]
    result = packer.pack(iter(content))

    zf = zipfile.ZipFile(io.BytesIO(result))
    names = set(zf.namelist())
    assert "run.pyc" in names
    assert "lib/util.pyc" in names
    assert "run.py" not in names


def test_pack_non_py_passthrough() -> None:
    """Test that non-.py files are packed as-is without compilation."""
    compiler = PycCompiler(importlib.util.MAGIC_NUMBER)
    packer = Packer(compiler)

    content = [("data.json", b'{"key": "value"}'), ("run.py", "pass")]
    result = packer.pack(iter(content))

    zf = zipfile.ZipFile(io.BytesIO(result))
    assert zf.read("data.json") == b'{"key": "value"}'


def test_pack_no_compiler() -> None:
    """Test that NoCompiler keeps .py files as-is."""
    packer = Packer(NoCompiler())

    content = [("run.py", "x = 1"), ("lib.py", b"y = 2")]
    result = packer.pack(iter(content))

    zf = zipfile.ZipFile(io.BytesIO(result))
    names = set(zf.namelist())
    assert "run.py" in names
    assert "lib.py" in names
    assert zf.read("run.py") == b"x = 1"
    assert zf.read("lib.py") == b"y = 2"


def test_pack_skips_invalid_py() -> None:
    """Test that files that fail compilation are skipped entirely."""
    compiler = PycCompiler(importlib.util.MAGIC_NUMBER)
    packer = Packer(compiler)

    content = [("good.py", "x = 1"), ("bad.py", "def !!!")]
    result = packer.pack(iter(content))

    zf = zipfile.ZipFile(io.BytesIO(result))
    names = set(zf.namelist())
    assert "good.pyc" in names
    assert "bad.py" not in names
    assert "bad.pyc" not in names


def test_mkzip_creates_deflated_zip() -> None:
    """Test that mkzip creates a writable deflated zip archive."""
    buf, zf = mkzip()
    assert zf.compression == zipfile.ZIP_DEFLATED

    with zf:
        zwrite(zf, zinfo("test.txt"), b"hello")

    result = zipfile.ZipFile(buf)
    assert result.read("test.txt") == b"hello"


def test_zinfo_fixed_timestamp() -> None:
    """Test that zinfo creates entries with a fixed timestamp."""
    info = zinfo("file.py")
    assert info.date_time == (1980, 0, 0, 0, 0, 0)
