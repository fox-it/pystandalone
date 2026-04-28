from __future__ import annotations

import io

import pytest

from pystandalone.chacha20 import Chacha20, decrypt
from tests.conftest import absolute_path


@pytest.mark.parametrize(
    ("path", "key", "iv"),
    [
        ("_data/chacha20_zero_iv.bin", b"\x00" * 32, b"\x00" * 8),
        ("_data/chacha20_unique_iv.bin", b"\x00" * 32, b"ABLAFLAFLADEADBE"),
    ],
)
@pytest.mark.parametrize(
    ("pos", "whence", "n", "expected"),
    [
        (1, io.SEEK_SET, -1, b"ello_world"),
        (64, io.SEEK_SET, 64, b""),
        (-10, io.SEEK_END, 10, b"ello_world"),
        (2, io.SEEK_CUR, 2, b"ll"),
    ],
)
def test_stream_seek_read(path: str, key: bytes, iv: bytes, pos: int, whence: int, n: int, expected: bytes) -> None:
    """Test that seeking and reading from the Chacha20 stream works as expected."""
    with absolute_path(path).open("rb") as fh:
        stream = Chacha20(fh, key=key, iv=iv)
        stream.seek(pos, whence)
        assert stream.read(n) == expected


@pytest.mark.parametrize(
    ("path", "key", "iv"),
    [
        ("_data/chacha20_zero_iv.bin", b"\x00" * 32, b"\x00" * 8),
        ("_data/chacha20_unique_iv.bin", b"\x00" * 32, b"ABLAFLAFLADEADBE"),
    ],
)
@pytest.mark.parametrize(
    ("pos", "whence", "n"),
    [
        (1, io.SEEK_SET, -1),
        (64, io.SEEK_SET, 64),
        (-10, io.SEEK_END, 10),
        (20, io.SEEK_CUR, 20),
    ],
)
def test_compare_stream_and_oneshot(path: str, key: bytes, iv: bytes, pos: int, whence: int, n: int) -> None:
    buf = absolute_path(path).read_bytes()

    stream = Chacha20(io.BytesIO(buf), key=key, iv=iv)
    oneshot = io.BytesIO(decrypt(buf, key=key, iv=iv))

    stream.seek(pos, whence)
    oneshot.seek(pos, whence)
    assert stream.read(n) == oneshot.read(n)
