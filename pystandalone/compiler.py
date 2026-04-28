from __future__ import annotations

import importlib
import io
import marshal
import platform
from typing import TYPE_CHECKING, BinaryIO, TextIO

from pystandalone import chacha20

if TYPE_CHECKING:
    from pathlib import Path


class Compiler:
    EXT = ""

    def compile(self, s: str | bytes, name: str | None = None, strip: bool = True) -> bytes:
        raise NotImplementedError

    def compile_file(self, path: Path, **kwargs) -> bytes:
        return self.compile(path.read_text(), **kwargs)

    def compile_fileobj(self, fh: TextIO | BinaryIO, **kwargs) -> bytes:
        return self.compile(fh.read(), **kwargs)


class NoCompiler(Compiler):
    def compile(self, s: str | bytes, name: str | None = None, strip: bool = True) -> bytes:
        return s.encode() if isinstance(s, str) else s


class PycCompiler(Compiler):
    EXT = "c"

    def __init__(self, magic: bytes, *, strict: bool = True):
        if (running_implementation := platform.python_implementation()).lower() != "cpython":
            raise RuntimeError(f"{running_implementation} is not supported for compiling. Please run with CPython.")

        if magic != importlib.util.MAGIC_NUMBER and strict:
            raise RuntimeError("Compiling with a different Python version than the target binary")

        self.magic = magic

    def compile(self, s: str | bytes, name: str | None = None, strip: bool = True) -> bytes:
        name = name or "<standalone>"

        cobj = compile(s, name, "exec", dont_inherit=True, optimize=2 if strip else -1)

        out = io.BytesIO()
        out.write(self.magic)
        out.write(b"\x00\x00\x00\x00")  # flags
        out.write(b"\x00\x00\x00\x00")  # timestamp
        out.write(b"\x00\x00\x00\x00")  # source size
        out.write(marshal.dumps(cobj))
        return out.getvalue()


class CryptCompiler(NoCompiler):
    def __init__(self, key: bytes, iv: bytes):
        self.key = key
        self.iv = iv

    def compile(self, s: str | bytes, name: str | None = None, strip: bool = True) -> bytes:
        return chacha20.encrypt(super().compile(s, name, strip), self.key, self.iv)
