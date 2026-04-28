from __future__ import annotations

import importlib
import io
import marshal
from typing import TYPE_CHECKING

import pytest

from pystandalone.compiler import NoCompiler, PycCompiler

if TYPE_CHECKING:
    from pathlib import Path

MAGIC = importlib.util.MAGIC_NUMBER


def test_passthrough_compiler() -> None:
    """Test that NoCompiler returns .py files as-is without compilation."""
    c = NoCompiler()
    assert c.compile("x = 1") == b"x = 1"


def test_strict_rejects_wrong_magic() -> None:
    """Test that we reject compiling with a different Python version by default."""
    with pytest.raises(RuntimeError, match="different Python version"):
        PycCompiler(b"\x00\x00\x00\x00")


def test_strict_false_accepts_wrong_magic() -> None:
    """Test that we can disable strict mode to allow compiling with a different Python version."""
    c = PycCompiler(b"\x00\x00\x00\x00", strict=False)
    assert c.magic == b"\x00\x00\x00\x00"


def test_compile_str_produces_valid_pyc() -> None:
    """Test that compiling a string produces a valid .pyc file with the correct magic number and structure."""
    c = PycCompiler(MAGIC)
    result = c.compile("x = 1 + 2")

    assert result[:4] == MAGIC
    # flags, timestamp, source size = 12 bytes of zeros
    assert result[4:16] == b"\x00" * 12
    # remainder is a marshalled code object
    code = marshal.loads(result[16:])
    assert code.co_filename == "<standalone>"


def test_compile_str_custom_name() -> None:
    """Test that we can specify a custom filename for the code object when compiling a string."""
    c = PycCompiler(MAGIC)
    code = marshal.loads(c.compile("pass", name="custom.py")[16:])
    assert code.co_filename == "custom.py"


def test_compile_fileobj() -> None:
    """Test that compiling from a file-like object works."""
    c = PycCompiler(MAGIC)
    result = c.compile_fileobj(io.StringIO("y = 42"))
    code = marshal.loads(result[16:])
    assert code.co_filename == "<standalone>"


def test_compile_file(tmp_path: Path) -> None:
    """Test that compiling from a file path works and uses the correct filename in the code object."""
    src = tmp_path / "script.py"
    src.write_text("z = 99")

    c = PycCompiler(MAGIC)
    result = c.compile_file(src)
    code = marshal.loads(result[16:])
    assert code.co_filename == "<standalone>"
