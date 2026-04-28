from __future__ import annotations

import io
import struct
from typing import TYPE_CHECKING, BinaryIO

if TYPE_CHECKING:
    from collections.abc import Iterator

    from typing_extensions import Self


class Chacha20(io.RawIOBase):
    def __init__(self, fh: BinaryIO, key: bytes, iv: bytes) -> None:
        self.fh = fh
        self.key = key
        self.iv = iv

        self._offset_into_block = 0
        self._original_offset = 0
        if len(iv) == 16:
            # Compatibility with OpenSSL-like IV
            self._original_offset, self.iv = struct.unpack("<Q8s", iv)

        self._key_stream = _chacha20_xor_stream(self.key, self.iv, position=self._original_offset)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args) -> None:
        pass

    @property
    def closed(self) -> None:
        return self.fh.closed

    def seek(self, pos: int, whence: int = io.SEEK_SET) -> int:
        new_pos = self.fh.seek(pos, whence)
        pos, offset = divmod(new_pos, 64)

        block_low = (self._original_offset + pos) & 0xFFFFFFFF
        block_high = ((self._original_offset >> 32) + (pos >> 32)) & 0xFFFFFFFF

        self._key_stream = _chacha20_xor_stream(self.key, self.iv, block_high << 32 | block_low)
        for _ in range(offset):
            next(self._key_stream)
        return new_pos

    def read(self, n: int = -1) -> bytes:
        return bytes(a ^ x for a, x in zip(self.fh.read(n), self._key_stream, strict=False))

    def readable(self) -> bool:
        return self.fh.readable()

    def readinto(self, buffer: memoryview) -> int:
        data = self.read(len(buffer))
        size = len(data)
        buffer[:size] = data
        return size

    def seekable(self) -> bool:
        return self.fh.seekable()

    def tell(self) -> int:
        return self.fh.tell()

    def close(self) -> None:
        self.fh.close()

    def flush(self) -> None:
        self.fh.flush()


def _chacha20_xor_stream(key: bytes, iv: bytes, position: int = 0) -> Iterator[int]:
    """Generate a chacha20 xor stream."""
    if not isinstance(position, int):
        raise TypeError("position must be an integer")

    if position.bit_length() > 64:
        raise ValueError("position can't be larger than 64 bits")

    if not isinstance(key, bytes):
        raise TypeError("key must be a bytes-like object")

    if not isinstance(iv, bytes):
        raise TypeError("iv must be a bytes-like object")

    if len(key) != 32:
        raise ValueError("key must be 32 bytes")

    if len(iv) != 8:
        raise ValueError("iv must be 8 bytes")

    def rotate(v: int, c: int) -> int:
        return ((v << c) & 0xFFFFFFFF) | v >> (32 - c)

    def quarter_round(x: int, a: int, b: int, c: int, d: int) -> None:
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF
        x[d] = rotate(x[d] ^ x[a], 16)
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF
        x[b] = rotate(x[b] ^ x[c], 12)
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF
        x[d] = rotate(x[d] ^ x[a], 8)
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF
        x[b] = rotate(x[b] ^ x[c], 7)

    ctx = [0] * 16
    # "expand 32-byte k"
    ctx[:4] = (1634760805, 857760878, 2036477234, 1797285236)
    ctx[4:12] = struct.unpack("<8L", key)
    ctx[12:14] = struct.unpack("<LL", struct.pack("<Q", position))
    ctx[14:16] = struct.unpack("<LL", iv)

    _s = struct.Struct("<16L")
    while 1:
        x = list(ctx)
        for _ in range(10):
            quarter_round(x, 0, 4, 8, 12)
            quarter_round(x, 1, 5, 9, 13)
            quarter_round(x, 2, 6, 10, 14)
            quarter_round(x, 3, 7, 11, 15)
            quarter_round(x, 0, 5, 10, 15)
            quarter_round(x, 1, 6, 11, 12)
            quarter_round(x, 2, 7, 8, 13)
            quarter_round(x, 3, 4, 9, 14)

        yield from _s.pack(*((x[i] + ctx[i]) & 0xFFFFFFFF for i in range(16)))

        ctx[12] = (ctx[12] + 1) & 0xFFFFFFFF
        if ctx[12] == 0:
            ctx[13] = (ctx[13] + 1) & 0xFFFFFFFF


def crypt(data: bytes, key: bytes, iv: bytes | None = None, position: int = 0) -> bytes:
    """Encrypt or decrypt with the chacha20 cipher."""
    if not isinstance(data, bytes):
        raise TypeError("data must be a bytes-like object")

    if not key:
        raise ValueError("key is empty")

    if not isinstance(key, bytes):
        raise TypeError("key must be a bytes-like object")

    if len(key) != 32:
        raise ValueError("key must be 32 bytes")

    if not iv:
        iv = b"\x00" * 8

    if not isinstance(iv, bytes):
        raise TypeError("iv must be a bytes-like object")

    if len(iv) == 16:
        # Compatibility with OpenSSL-like IV
        position, iv = struct.unpack("<Q8s", iv)

    if len(iv) != 8:
        raise ValueError("iv must be 8 bytes")

    return bytes(a ^ b for a, b in zip(data, _chacha20_xor_stream(key, iv, position), strict=False))


encrypt = crypt
decrypt = crypt
