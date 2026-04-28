from __future__ import annotations

import _io
import _pyio
import builtins
import dataclasses
import errno
import glob
import io
import os
import pathlib
import re
import ssl
import stat
import sys
import zipimport
from typing import IO, TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator


def is_version(major: int, minor: int) -> bool:
    return sys.version_info[0] == major and sys.version_info[1] == minor


def min_version(major: int, minor: int) -> bool:
    return sys.version_info >= (major, minor)


CASE_INSENSITIVE = zipimport.path_sep == "\\"

RE_MAGIC = re.compile("<library>|<bootstrap>|<payload>")

_zipfs_cache = {}


def _get_zipfs(archive: str) -> tuple[zipimport.zipimporter, dict[str, dict | tuple]]:
    if archive in _zipfs_cache:
        importer, fs = _zipfs_cache[archive]
    else:
        fs = {}
        importer = next(imp for imp in sys.meta_path if getattr(imp, "archive", None) == archive)

        # zipimport._zip_directory_cache is fragile but so far stable across 3.10-3.15, use it until it breaks
        for toc_entry in zipimport._zip_directory_cache.get(archive, {}).values():
            # (path, compress, data_size, file_size, file_offset, time, date, crc)
            if toc_entry is None:
                # None entries are inserted for implicit directories, but we handle those ourselves, so skip them
                continue

            path = toc_entry[0]
            if CASE_INSENSITIVE:
                path = path.lower()

            if zipimport.alt_path_sep:
                path = path.replace(zipimport.alt_path_sep, zipimport.path_sep)

            obj = fs
            dirname, _, basename = path.rpartition(zipimport.path_sep)
            for part in dirname.split(zipimport.path_sep):
                if part not in obj:
                    obj[part] = {}
                obj = obj[part]

            obj[basename] = toc_entry

        _zipfs_cache[archive] = (importer, fs)

    return importer, fs


def zipfs_get_entry(archive: str, path: str) -> dict | tuple:
    if CASE_INSENSITIVE:
        path = path.lower()

    if zipimport.alt_path_sep:
        path = path.replace(zipimport.alt_path_sep, zipimport.path_sep)

    _, obj = _get_zipfs(archive)
    for part in path.split(zipimport.path_sep):
        if part == "":
            continue

        try:
            obj = obj[part]
        except KeyError:
            raise OSError(errno.ENOENT, "", path)

    return obj


def zipfs_stat(archive: str, path: str) -> os.stat_result:
    entry = zipfs_get_entry(archive, path)
    if isinstance(entry, dict):
        return os.stat_result([stat.S_IFDIR | 0o777, id(entry), 0, 0, 0, 0, 0, 0, 0, 0])

    # (path, compress, data_size, file_size, file_offset, time, date, crc)
    _, _, _, file_size, file_offset, _, _, _ = entry
    # mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime
    return os.stat_result([stat.S_IFREG | 0o777, file_offset, 0, 0, 0, 0, file_size, 0, 0, 0])


def zipfs_find_magic(path: str | pathlib.Path) -> tuple[str, str] | None:
    path = str(path)
    if (match := RE_MAGIC.search(path)) is None:
        return None

    return path[match.start() : match.end()], path[match.start() :]


# io patches


def _monkey_open(path: str | pathlib.Path, *args, **kwargs) -> IO:
    if zipfs_find_magic(path) is None:
        return _io.open(path, *args, **kwargs)
    # Forward to pyio so we can catch it with the pyio monkey patch
    return _pyio.open(path, *args, **kwargs)


builtins.open = _monkey_open
io.OpenWrapper = _monkey_open


_pyio_FileIO = _pyio.FileIO


def _monkey_FileIO(path: str, *args, **kwargs) -> io.FileIO:
    if (magic := zipfs_find_magic(path)) is None:
        return _pyio_FileIO(path, *args, **kwargs)

    archive, mpath = magic
    importer, _ = _get_zipfs(archive)

    if mpath == archive:
        # Return the whole archive
        # ._buf is added by our pystandalone patches
        data = importer._buf
    else:
        toc_entry = zipfs_get_entry(archive, mpath)
        if isinstance(toc_entry, dict):
            raise IsADirectoryError(f"Is a directory: {mpath!r}")

        # zipimport._get_data is fragile but so far stable across 3.10-3.15, use it until it breaks
        data = zipimport._get_data(importer.archive, toc_entry, importer._buf)

    buf = io.BytesIO(data)
    # Patch some attributes to make it look more like a real FileIO object
    buf._blksize = io.DEFAULT_BUFFER_SIZE
    buf._isatty_open_only = lambda *args, **kwargs: False

    return buf


_pyio.FileIO = _monkey_FileIO
io.FileIO = _monkey_FileIO


# os patches

_os_stat = os.stat
_os_lstat = os.lstat
_os_access = os.access


def _monkey_stat(path: str, *args, **kwargs) -> os.stat_result:
    if (magic := zipfs_find_magic(path)) is None:
        return _os_stat(path, *args, **kwargs)

    archive, mpath = magic
    return zipfs_stat(archive, mpath)


def _monkey_lstat(path: str, *args, **kwargs) -> os.stat_result:
    if (magic := zipfs_find_magic(path)) is None:
        return _os_lstat(path, *args, **kwargs)

    archive, mpath = magic
    return zipfs_stat(archive, mpath)


def _monkey_access(path: str, mode: int, *args, **kwargs) -> bool:
    if zipfs_find_magic(path) is None:
        return _os_access(path, mode, *args, **kwargs)

    if mode & os.W_OK:
        return False

    if (magic := zipfs_find_magic(path)) is None:
        return _os_access(path, mode)

    archive, mpath = magic
    try:
        zipfs_stat(archive, mpath)
    except OSError:
        return False

    return True


os.stat = _monkey_stat
os.lstat = _monkey_lstat
os.access = _monkey_access


_os_listdir = os.listdir


def _monkey_listdir(path: str) -> list[str]:
    if (magic := zipfs_find_magic(path)) is None:
        return _os_listdir(path)

    archive, mpath = magic
    toc_entry = zipfs_get_entry(archive, mpath)
    if not isinstance(toc_entry, dict):
        raise NotADirectoryError(f"Not a directory: {mpath!r}")

    return list(toc_entry.keys())


os.listdir = _monkey_listdir

_os_scandir = os.scandir


class ScandirIterator:
    def __init__(self, iterator: Iterator[DirEntry]):
        self._iterator = iterator

    def __del__(self):
        self.close()

    def __enter__(self):
        return self._iterator

    def __exit__(self, *args, **kwargs):
        return False

    def __iter__(self):
        return self._iterator

    def __next__(self, *args):
        return next(self._iterator, *args)

    def close(self) -> None:
        pass


class DirEntry:
    def __init__(self, path: str, toc_entry: dict | tuple):
        self.toc_entry = toc_entry

        self.name = path.rpartition(zipimport.path_sep)[2]
        self.path = path

    def inode(self) -> int:
        return self.toc_entry[4] if isinstance(self.toc_entry, tuple) else id(self.toc_entry)

    def is_dir(self, follow_symlinks: bool = True) -> builtins.bool:
        return isinstance(self.toc_entry, dict)

    def is_file(self, follow_symlinks: bool = True) -> builtins.bool:
        return isinstance(self.toc_entry, tuple)

    def is_symlink(self) -> bool:
        return False

    def stat(self, follow_symlinks: bool = True) -> os.stat_result:
        if isinstance(self.toc_entry, dict):
            return os.stat_result([stat.S_IFDIR, 0, 0, 0, 0, 0, 0, 0, 0, 0])

        # (path, compress, data_size, file_size, file_offset, time, date, crc)
        _, _, _, file_size, _, _, _, _ = self.toc_entry
        return os.stat_result([stat.S_IFREG, 0, 0, 0, 0, 0, file_size, 0, 0, 0])


def _monkey_scandir(path: str) -> ScandirIterator:
    if (magic := zipfs_find_magic(path)) is None:
        return _os_scandir(path)

    archive, mpath = magic
    toc_entry = zipfs_get_entry(archive, mpath)

    if not isinstance(toc_entry, dict):
        raise NotADirectoryError(f"Not a directory: {mpath!r}")

    def iterator() -> Iterator[DirEntry]:
        for name, entry in toc_entry.items():
            yield DirEntry(zipimport.path_sep.join([mpath, name]), entry)

    return ScandirIterator(iterator())


os.scandir = _monkey_scandir


# Windows specific os.path patches
if os.name == "nt" and min_version(3, 12):
    import genericpath

    os.path.isdir = genericpath.isdir
    os.path.isfile = genericpath.isfile
    os.path.islink = genericpath.islink
    os.path.exists = genericpath.exists
    if min_version(3, 13):
        os.path.lexists = genericpath.lexists


# ssl patches

_ssl_SSLContext_load_verify_locations = ssl.SSLContext.load_verify_locations


def _monkey_load_verify_locations(
    self: ssl.SSLContext, cafile: str | None = None, capath: str | None = None, cadata: str | bytes | None = None
) -> ssl.SSLContext:
    if zipfs_find_magic(cafile) is None:
        return _ssl_SSLContext_load_verify_locations(self, cafile, capath, cadata)

    return _ssl_SSLContext_load_verify_locations(self, None, None, pathlib.Path(cafile).read_bytes())


ssl.SSLContext.load_verify_locations = _monkey_load_verify_locations


# dataclasses patches

_dataclasses__process_class = dataclasses._process_class


def _monkey__process_class(cls, *args, **kwargs):  # noqa
    # We strip C docstrings from the pystandalone binaries
    # This means that dataclasses can't generate __doc__ strings for the generated classes,
    # which causes them to fail when trying to generate __text_signature__
    # This is fixed in python-3.11.4 with a try/except, but for convenience we just patch it here
    cls.__doc__ = cls.__name__
    return _dataclasses__process_class(cls, *args, **kwargs)


dataclasses._process_class = _monkey__process_class


# pathlib patches
if hasattr(pathlib, "_NormalAccessor"):
    pathlib._NormalAccessor.stat = staticmethod(_monkey_stat)
    pathlib._NormalAccessor.lstat = staticmethod(_monkey_lstat)
    pathlib._NormalAccessor.open = staticmethod(_monkey_open)
    pathlib._NormalAccessor.listdir = staticmethod(_monkey_listdir)
    pathlib._NormalAccessor.scandir = staticmethod(_monkey_scandir)

# glob patches
if hasattr(glob, "_StringGlobber") and is_version(3, 13):
    glob._StringGlobber.scandir = staticmethod(_monkey_scandir)

# Apply io patches last
io.open = _monkey_open
