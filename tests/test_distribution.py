from __future__ import annotations

import re
from typing import TYPE_CHECKING

from pystandalone.distribution import Architecture, Target

if TYPE_CHECKING:
    from pystandalone.distribution import Distribution


def test_distribution_metadata(linux_distribution: Distribution) -> None:
    """Test that distribution metadata contains expected keys."""
    metadata = linux_distribution.metadata
    assert "python_version" in metadata
    assert "target_triple" in metadata
    assert "python_bytecode_magic_number" in metadata
    assert "python_exe" in metadata


def test_distribution_version(linux_distribution: Distribution) -> None:
    """Test that distribution version matches expected major.minor.patch format."""
    assert re.match(r"\d+\.\d+\.\d+", linux_distribution.version)


def test_distribution_target_arch(linux_distribution: Distribution) -> None:
    """Test that the distribution target and architecture match the expected values."""
    assert linux_distribution.target == Target.LINUX
    assert linux_distribution.arch == Architecture.X86_64


def test_distribution_bytecode_magic(linux_distribution: Distribution) -> None:
    """Test that distribution bytecode magic is 4 bytes."""
    magic = linux_distribution.bytecode_magic
    assert isinstance(magic, bytes)
    assert len(magic) == 4


def test_distribution_read_python_exe(linux_distribution: Distribution) -> None:
    """Test that we can read the Python executable from the distribution."""
    exe = linux_distribution.read_python_exe()
    assert len(exe) > 0


def test_distribution_pack_library(linux_distribution: Distribution) -> None:
    """Test that pack_library yields stdlib modules."""
    packed = dict(linux_distribution.pack_library())

    assert "os.py" in packed
    assert "json/__init__.py" in packed
    assert isinstance(packed["os.py"], bytes)


def test_distribution_pack_library_exclude(linux_distribution: Distribution) -> None:
    """Test that pack_library exclude filtering works."""
    packed = dict(linux_distribution.pack_library(exclude=["json"]))

    assert "os.py" in packed
    filenames = set(packed.keys())
    assert not any(f.startswith("json/") or f == "json.py" for f in filenames)


def test_distribution_pack_library_include(linux_distribution: Distribution) -> None:
    """Test that pack_library include overrides default excludes."""
    packed_without = dict(linux_distribution.pack_library())
    packed_with = dict(linux_distribution.pack_library(include=["sqlite3"]))

    assert "sqlite3" not in {f.split("/")[0] for f in packed_without}
    assert any(f.startswith("sqlite3/") for f in packed_with)
