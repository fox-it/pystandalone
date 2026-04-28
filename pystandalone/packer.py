from __future__ import annotations

import io
import logging
import zipfile
from typing import TYPE_CHECKING

from pystandalone.compiler import NoCompiler

if TYPE_CHECKING:
    from collections.abc import Iterator

    from pystandalone.compiler import Compiler

log = logging.getLogger(__name__)


COMPRESSION = zipfile.ZIP_DEFLATED


class Packer:
    """Take source code and pack it into a zip file, optionally compiling .py files to .pyc along the way.

    Args:
        compiler: The compiler to use for compiling .py files.
    """

    def __init__(self, compiler: Compiler | None = None):
        self.compiler = compiler or NoCompiler()

    def pack(self, content: Iterator[tuple[str, str | bytes]]) -> bytes:
        """Pack the given content into a zip file, compiling .py if necessary.

        Args:
            content: An iterator of ``(path, content)`` tuples to pack. Paths should be relative.
        """
        buf, zipf = mkzip()
        seen = set()
        with zipf:
            for path, data in content:
                zippath = path

                if path.endswith(".py"):
                    try:
                        data = self.compiler.compile(data, name=path)
                        zippath += self.compiler.EXT
                    except Exception as e:
                        log.error("Failed to compile %s, skipping", path)  # noqa: TRY400
                        log.debug("", exc_info=e)
                        continue

                if zippath in seen:
                    continue
                seen.add(zippath)

                zwrite(zipf, zinfo(zippath), data)

        return buf.getvalue()


def zinfo(name: str) -> zipfile.ZipInfo:
    """Create a ZipInfo with a fixed timestamp.

    Args:
        name: The name of the file in the zip archive.
    """
    return zipfile.ZipInfo(name, (1980, 0, 0, 0, 0, 0))


def zwrite(zipf: zipfile.ZipFile, info: zipfile.ZipInfo, s: bytes) -> None:
    """Write bytes to a ZipFile with a given ZipInfo.

    Args:
        zipf: The ZipFile object to write to.
        info: The ZipInfo object containing metadata for the file.
        s: The bytes to write to the zip file.
    """
    zipf.writestr(info, s, compress_type=zipf.compression)


def mkzip() -> tuple[io.BytesIO, zipfile.ZipFile]:
    """Create an in-memory ZipFile for writing.

    Returns:
        A tuple containing the BytesIO buffer and the ZipFile object.
    """
    buf = io.BytesIO()
    return buf, zipfile.ZipFile(buf, mode="w", compression=COMPRESSION)
