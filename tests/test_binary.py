from __future__ import annotations

import struct
from typing import TYPE_CHECKING

import lief

from pystandalone.binary import pack_zip, patch

if TYPE_CHECKING:
    from pystandalone.distribution import Distribution


def test_pack_zip_single() -> None:
    """Test that pack_zip packs a single zip with a size prefix."""
    data = b"PK\x03\x04fake_zip_data"
    result = pack_zip([data])

    size = struct.unpack("<I", result[:4])[0]
    assert size == len(data)
    assert result[4:] == data


def test_pack_zip_multiple() -> None:
    """Test that pack_zip packs multiple zips sequentially with size prefixes."""
    zip1 = b"zip_one"
    zip2 = b"zip_two_longer"
    result = pack_zip([zip1, zip2])

    offset = 0
    for expected in [zip1, zip2]:
        size = struct.unpack("<I", result[offset : offset + 4])[0]
        assert size == len(expected)
        assert result[offset + 4 : offset + 4 + size] == expected
        offset += 4 + size

    assert offset == len(result)


def test_pack_zip_empty() -> None:
    """Test that pack_zip with no zips returns empty bytes."""
    assert pack_zip([]) == b""


def test_patch_elf(linux_distribution: Distribution) -> None:
    """Test that patching an ELF binary writes the payload into the .pystandalone section."""
    payload = b"\x01\x02\x03\x04" * 16

    result = patch(linux_distribution, payload)
    elf = lief.ELF.parse(result)
    section = elf.get_section(".pystandalone")
    section_data = bytes(section.content)

    assert section_data[: len(payload)] == payload


def test_patch_pe(windows_distribution: Distribution) -> None:
    """Test that patching a PE binary writes the payload into the RCDATA resource."""
    payload = b"\x01\x02\x03\x04" * 16

    result = patch(windows_distribution, payload)
    pe = lief.PE.parse(result)

    found = False
    for node in pe.resources.childs:
        if node.id == lief.PE.ResourcesManager.TYPE.RCDATA:
            data = bytes(next(next(node.childs).childs).content)
            assert data == payload
            found = True
            break

    assert found


def test_patch_macho(macos_distribution: Distribution) -> None:
    """Test that patching a Mach-O binary writes the payload into the __pystandalone section."""
    payload = b"\x01\x02\x03\x04" * 16

    result = patch(macos_distribution, payload)
    fat = lief.MachO.parse(result)

    for macho in fat:
        section = macho.get_section("__pystandalone")
        section_data = bytes(section.content)
        assert section_data[: len(payload)] == payload
