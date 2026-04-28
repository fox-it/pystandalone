from __future__ import annotations

import contextlib
import hashlib
import io
import json
import logging
import os
import platform
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request
from dataclasses import dataclass
from enum import Enum
from functools import cache, cached_property
from itertools import groupby
from operator import attrgetter
from pathlib import Path
from typing import TYPE_CHECKING

import tqdm
from platformdirs import user_data_path

from pystandalone import available

if TYPE_CHECKING:
    from collections.abc import Iterator
    from tarfile import TarFile

    from typing_extensions import Self

log = logging.getLogger(__name__)


DEFAULT_INCLUDE = {
    "encodings.cp437",
}
DEFAULT_EXCLUDE = {
    "__phello__.foo.py",
    "_markupbase.py",
    "_pydecimal.py",
    "_sysconfigdata",  # Build artifact
    "aifc.py",
    "antigravity.py",
    "asynchat.py",
    "asyncore.py",
    "bdb.py",
    "cgi.py",
    "cgitb.py",
    "chunk.py",
    "colorsys.py",
    "config-",  # Build artifact
    "cProfile.py",
    "crypt.py",
    "ctypes.test",
    "curses",
    "dbm",
    "decimal.py",
    "difflib.py",
    "distutils",
    "doctest.py",
    "encodings.cp",
    "encodings.euc",
    "encodings.gb",
    "encodings.hp",
    "encodings.iso",
    "encodings.koi",
    "encodings.kz",
    "encodings.mac",
    "encodings.shift",
    "ensurepip",
    "ftplib.py",
    "html",
    "idlelib",
    "imaplib.py",
    "imghdr.py",
    "lib2to3",
    "LICENSE.txt",
    "mailbox.py",
    "mailcap.py",
    "msilib",
    "multiprocessing",
    "netrc.py",
    "nntplib.py",
    "optparse.py",
    "pdb.py",
    "pickletools.py",
    "pipes.py",
    "poplib.py",
    "profile.py",
    "pstats.py",
    "pyclbr.py",
    "pydoc.py",
    "pydoc_data",
    "sched.py",
    "secrets.py",
    "site-packages",
    "smtpd.py",
    "smtplib.py",
    "sndhdr.py",
    "sqlite3",
    "statistics.py",
    "sunau.py",
    "symtable.py",
    "tabnanny.py",
    "telnetlib.py",
    "test",
    "this.py",
    "timeit.py",
    "tkinter",
    "trace.py",
    "unittest",
    "turtle.py",
    "turtledemo",
    "uu.py",
    "venv",
    "wave.py",
    "webbrowser.py",
    "wsgiref",
    "xdrlib.py",
    "xmlrpc",
    "zipapp.py",
}


class Target(Enum):
    LINUX = "linux"
    WINDOWS = "windows"
    MACOS = "macos"

    def __str__(self) -> str:
        return self.value

    @classmethod
    def from_current(cls) -> Self:
        if sys.platform.startswith("linux"):
            return cls.LINUX
        if sys.platform.startswith("win"):
            return cls.WINDOWS
        if sys.platform.startswith("darwin"):
            return cls.MACOS
        raise RuntimeError(f"Unsupported platform {sys.platform}")

    @classmethod
    def from_triple(cls, triple: str) -> Self:
        if "-apple-darwin" in triple:
            return Target.MACOS
        if "-unknown-linux-" in triple:
            return Target.LINUX
        if "-pc-windows-" in triple:
            return Target.WINDOWS
        raise ValueError(f"Unsupported target triple {triple}")


class Architecture(Enum):
    I686 = "i686"
    X86_64 = "x86_64"
    AARCH64 = "aarch64"

    def __str__(self) -> str:
        return self.value

    @classmethod
    def from_current(cls) -> Self:
        arch = platform.machine().lower()
        if arch in ("i686", "i386"):
            return cls.I686
        if arch in ("x86_64", "amd64"):
            return cls.X86_64
        if arch in ("aarch64", "arm64"):
            return cls.AARCH64
        raise RuntimeError(f"Unsupported architecture {arch}")

    @classmethod
    def from_triple(cls, triple: str) -> Self:
        return cls(triple.split("-")[0])


@dataclass
class DistributionInfo:
    version: str
    target_triple: str
    url: str
    digest: str

    @property
    def target(self) -> Target:
        return Target.from_triple(self.target_triple)

    @property
    def arch(self) -> Architecture:
        return Architecture.from_triple(self.target_triple)

    def ensure(self, progress: bool = False) -> Path:
        cache = cache_path()

        archive_name = urllib.parse.urlparse(self.url).path.split("/")[-1]
        archive_path = cache / archive_name
        lock_path = cache / (archive_name + ".lock")

        with _file_lock(lock_path):
            if not archive_path.exists() or checksum(archive_path) != self.digest:
                log.info(
                    "Downloading distribution archive for Python %s (target: %s, arch: %s)",
                    self.version,
                    self.target.value,
                    self.arch.value,
                )

                fd, tmp_name = tempfile.mkstemp(prefix=archive_name, suffix=".tmp", dir=cache)
                tmp_path = Path(tmp_name)
                try:
                    os.close(fd)
                    download(self.url, tmp_path, name=archive_name, progress=progress)

                    if checksum(tmp_path) != self.digest:
                        raise ValueError("Downloaded file has an invalid digest")

                    tmp_path.replace(archive_path)
                finally:
                    tmp_path.unlink(missing_ok=True)

        return archive_path

    def get(self, progress: bool = False) -> Distribution:
        return Distribution(self.ensure(progress))


@contextlib.contextmanager
def _file_lock(path: Path) -> Iterator[None]:
    """Cross-platform file lock using fcntl (Unix) or LockFileEx (Windows)."""
    fd = os.open(path, os.O_CREAT | os.O_RDWR)
    try:
        if sys.platform == "win32":
            import ctypes
            import ctypes.wintypes
            import msvcrt

            class OVERLAPPED(ctypes.Structure):
                _fields_ = (
                    ("Internal", ctypes.wintypes.LPARAM),
                    ("InternalHigh", ctypes.wintypes.LPARAM),
                    ("Offset", ctypes.wintypes.DWORD),
                    ("OffsetHigh", ctypes.wintypes.DWORD),
                    ("hEvent", ctypes.wintypes.HANDLE),
                )

            LOCKFILE_EXCLUSIVE_LOCK = 0x0002
            if not ctypes.windll.kernel32.LockFileEx(
                ctypes.wintypes.HANDLE(msvcrt.get_osfhandle(fd)),
                ctypes.wintypes.DWORD(LOCKFILE_EXCLUSIVE_LOCK),
                ctypes.wintypes.DWORD(0),
                ctypes.wintypes.DWORD(1),
                ctypes.wintypes.DWORD(0),
                ctypes.byref(OVERLAPPED()),
            ):
                raise ctypes.WinError()
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def cache_path() -> Path:
    return user_data_path("pystandalone", ensure_exists=True)


def download(url: str, path: Path, name: str | None = None, progress: bool = False) -> None:
    with urllib.request.urlopen(url) as response:
        total = response.headers.get("Content-Length")
        total = int(total) if total else None

        if progress:
            bar = tqdm.tqdm(total=total, unit="B", unit_scale=True, desc=name or path.name)
        else:
            bar = contextlib.nullcontext()

        with bar, path.open("wb") as fh:
            while chunk := response.read(io.DEFAULT_BUFFER_SIZE):
                fh.write(chunk)

                if progress:
                    bar.update(len(chunk))


def checksum(path: Path) -> str:
    ctx = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(io.DEFAULT_BUFFER_SIZE), b""):
            ctx.update(chunk)
    return ctx.hexdigest()


@cache
def get_distribution_map() -> dict[str, dict[Target, dict[Architecture, DistributionInfo]]]:
    result = {}

    distributions = [DistributionInfo(*entry) for entry in available.DISTRIBUTIONS]
    for version, it_version in groupby(distributions, attrgetter("version")):
        result.setdefault(version, {})

        for target, it_target in groupby(it_version, attrgetter("target")):
            result[version].setdefault(target, {})

            for arch, it_arch in groupby(it_target, attrgetter("arch")):
                if (target, arch) == (Target.LINUX, Architecture.X86_64):
                    # For Linux x86_64, prefer musl builds
                    it_arch = filter(lambda d: "-musl" in d.target_triple, it_arch)
                elif (target, arch) == (Target.LINUX, Architecture.AARCH64):
                    # For Linux aarch64, prefer libc builds (as the musl builds are not static yet)
                    it_arch = filter(lambda d: "-gnu" in d.target_triple, it_arch)

                # Take the most recent build
                result[version][target][arch] = sorted(it_arch, key=attrgetter("url"))[-1]

    return result


class Distribution:
    """Distribution archive utility class.

    Provides convenience methods for extracting data and information from distribution archives.
    """

    def __init__(self, path: Path):
        self.path = path
        self.tar = None

    def __repr__(self) -> str:
        return f"<Distribution path={self.path}>"

    def open(self) -> TarFile:
        return tarfile.open(self.path, mode="r")

    @cached_property
    def metadata(self) -> dict:
        with self.open() as tf:
            try:
                return json.load(tf.extractfile("python/PYSTANDALONE.json"))
            except Exception:
                raise ValueError("Invalid distribution archive")

    @property
    def version(self) -> str:
        return self.metadata["python_version"]

    @property
    def major_minor_version(self) -> str:
        version = self.version
        return ".".join(version.split(".")[:2])

    @property
    def target_triple(self) -> str:
        return self.metadata["target_triple"]

    @property
    def target(self) -> Target:
        return Target.from_triple(self.target_triple)

    @property
    def arch(self) -> Architecture:
        return Architecture.from_triple(self.target_triple)

    @property
    def bytecode_magic(self) -> bytes:
        return bytes.fromhex(self.metadata["python_bytecode_magic_number"])

    def read_python_exe(self) -> bytes:
        with self.open() as tf:
            return tf.extractfile(f"python/{self.metadata['python_exe']}").read()

    def pack_library(
        self, include: list[str] | None = None, exclude: list[str] | None = None
    ) -> Iterator[tuple[str, bytes]]:
        include = set(include) if include else set()
        exclude = set(exclude) if exclude else set()

        include |= DEFAULT_INCLUDE
        exclude |= DEFAULT_EXCLUDE

        library_path = f"python/{self.metadata['python_stdlib']}/"

        include = tuple(include)
        exclude = tuple(exclude)

        with self.open() as tf:
            for member in tf.getmembers():
                if not member.name.startswith(library_path) or not member.isreg() or "__pycache__" in member.name:
                    continue

                relative_path = member.name[len(library_path) :]
                module_name = relative_path.replace("/", ".")

                if module_name.startswith(include) or not module_name.startswith(exclude):
                    yield (relative_path, tf.extractfile(member).read())


if __name__ == "__main__":
    import re

    RELEASES_URL = "https://api.github.com/repos/fox-it/python-build-pystandalone/releases/latest"
    RE_ASSET = re.compile(r"cpython-(\d+\.\d+)\.[^+]+\+\d+-(.+)-install_only_stripped\.tar\.gz")

    request = urllib.request.Request(RELEASES_URL, headers={"Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(request) as response:
        release = json.loads(response.read())

    entries = []
    for asset in release["assets"]:
        name = asset["name"]

        if "freethreaded" in name:
            continue

        if (match := RE_ASSET.fullmatch(name)) is None:
            continue

        version = match.group(1)
        triple = match.group(2)
        url = asset["browser_download_url"]
        digest = asset["digest"].removeprefix("sha256:")

        entries.append((version, triple, url, digest))

    entries.sort(key=lambda e: (e[0], e[1]))

    lines = []
    for version, triple, url, digest in entries:
        lines.append(f'    (\n        "{version}",\n        "{triple}",\n        "{url}",\n        "{digest}",\n    ),')

    output = "from __future__ import annotations\n\nDISTRIBUTIONS = [\n" + "\n".join(lines) + "\n]\n"

    output_path = Path(__file__).parent / "available.py"
    output_path.write_text(output)

    print(f"Wrote {len(entries)} distributions to {output_path}")
