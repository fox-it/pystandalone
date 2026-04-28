from __future__ import annotations

import urllib.error
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from pystandalone.distribution import Architecture, Target, get_distribution_map

if TYPE_CHECKING:
    from pystandalone.distribution import Distribution

DISTRIBUTIONS = get_distribution_map()
VERSIONS = sorted(DISTRIBUTIONS.keys())


def absolute_path(path: str) -> Path:
    return Path(__file__).parent / path


def _get_distribution(version: str, target: Target, arch: Architecture) -> Distribution:
    try:
        info = DISTRIBUTIONS[version][target][arch]
    except KeyError:
        pytest.skip(f"No distribution available for {version} {target.value} {arch.value}")

    try:
        return info.get()
    except urllib.error.URLError as e:
        pytest.skip(f"Unable to download distribution: {e}")


@pytest.fixture(scope="session")
def linux_distribution() -> Distribution:
    return _get_distribution("3.12", Target.LINUX, Architecture.X86_64)


@pytest.fixture(scope="session")
def windows_distribution() -> Distribution:
    return _get_distribution("3.12", Target.WINDOWS, Architecture.X86_64)


@pytest.fixture(scope="session")
def macos_distribution() -> Distribution:
    return _get_distribution("3.12", Target.MACOS, Architecture.AARCH64)


@pytest.fixture(scope="session", params=VERSIONS)
def native_distribution(request: pytest.FixtureRequest) -> Distribution:
    try:
        target = Target.from_current()
        arch = Architecture.from_current()
    except RuntimeError as e:
        pytest.skip(str(e))

    return _get_distribution(request.param, target, arch)
