from __future__ import annotations

import io
import logging
import os
import struct
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import lief

from pystandalone.codesign import adhoc_sign
from pystandalone.distribution import Target

if TYPE_CHECKING:
    from pystandalone.distribution import Distribution

log = logging.getLogger(__name__)


def pack_zip(zips: list[bytes]) -> bytes:
    """Pack multiple zip files into a single binary blob with a size prefix."""
    buf = io.BytesIO()
    for zipf in zips:
        buf.write(struct.pack("<I", len(zipf)))
        buf.write(zipf)

    return buf.getvalue()


def patch(dist: Distribution, payload: bytes) -> bytes:
    """Patch the target binary with the given payload."""
    binary = dist.read_python_exe()
    if dist.target == Target.WINDOWS:
        return patch_pe(binary, payload)
    if dist.target == Target.LINUX:
        return patch_elf(binary, payload)
    if dist.target == Target.MACOS:
        return patch_macho(binary, payload)
    raise RuntimeError(f"Unsupported target {dist.target}")


def patch_pe(binary: bytes, payload: bytes) -> bytes:
    """Patch a PE binary with the given payload."""
    if (pe := lief.PE.parse(io.BytesIO(binary))) is None:
        return binary

    for node in pe.resources.childs:
        if node.id == lief.PE.ResourcesManager.TYPE.RCDATA:
            data = next(next(node.childs).childs)
            data.content = payload  # type: ignore
            break

    return pe.write_to_bytes()


def patch_elf(binary: bytes, payload: bytes) -> bytes:
    """Patch an ELF binary with the given payload."""
    if (elf := lief.ELF.parse(io.BytesIO(binary))) is None:
        return binary

    section = elf.get_section(".pystandalone")

    # There are some issues with the way lief writes ELF files, so patch the payload in-place
    buf = bytearray(binary)
    buf[section.file_offset : section.file_offset + len(payload)] = payload

    return bytes(buf)


def patch_macho(binary: bytes, payload: bytes) -> bytes:
    """Patch a Mach-O binary with the given payload."""
    if (fat := lief.MachO.parse(io.BytesIO(binary))) is None:
        return binary

    for macho in fat:
        section = macho.get_section("__pystandalone")
        section.content = list(payload)  # type: ignore
        macho.remove_signature()

    fd, tmp_name = tempfile.mkstemp(suffix=".macho")
    tmp_path = Path(tmp_name)
    try:
        os.close(fd)
        fat.write(tmp_name)
        data = tmp_path.read_bytes()
    finally:
        tmp_path.unlink(missing_ok=True)

    return adhoc_sign(data)
