from __future__ import annotations

import configparser
import fnmatch
import importlib.util
import io
import logging
import os
import re
import subprocess
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

if TYPE_CHECKING:
    from collections.abc import Iterator
    from importlib.machinery import ModuleSpec

    from typing_extensions import Self


log = logging.getLogger(__name__)


RUN_MODULE_TEMPLATE = """
import sys
from {0} import {1}

if __name__ == '__main__':
    sys.exit({2}())
"""


class Source:
    """Source code for a pystandalone binary.

    This class represents the source code for a pystandalone binary.
    It can be created from a file path, a directory, or a .pystandalone spec file.
    It contains information about the entry point, included modules, and other metadata.
    """

    def __init__(self):
        self.run: str | None = None
        self.base: Path | None = None
        self.include_base = False

        self.library = set()
        self.modules = set()

        self.include = set()
        self.exclude = set()

        self.metadata = {}
        self.build = {}
        self.insert = {}

    @classmethod
    def from_path(cls, path: Path) -> Self:
        """Create a Source object from a file path.

        Args:
            path: The file path to create the Source object from.
        """
        source = cls()

        # Support spec entry selection with :entry syntax
        spec_entry = None
        if ":" in path.name:
            name, _, spec_entry = path.name.rpartition(":")
            path = path.with_name(name)

        if path.suffix in (".py", ".zip"):
            source.run = str(path)
            source.base = path.parent

        elif path.name.endswith(".pystandalone"):
            source._populate_from_spec(path, spec_entry)

        elif path.is_dir():
            if (spec_file := path.joinpath(".pystandalone")).exists():
                source._populate_from_spec(spec_file, spec_entry)
            elif path.joinpath("run.py").exists():
                source.run = "run.py"
                source.base = path
                source.include_base = True
            else:
                raise ValueError("No .pystandalone or run.py file in code directory")

        else:
            # TODO: support plain module entry points with :entry syntax
            raise ValueError("Unsupported source path")

        return source

    def _populate_from_spec(self, path: Path, entry: str | None = None) -> None:
        """Populate the Source object from a .pystandalone spec file."""
        spec = configparser.ConfigParser(allow_no_value=True)
        spec.read(path)

        run_entry = "run" + (f":{entry}" if entry else "")

        if not spec.has_option(run_entry, "entry"):
            raise ValueError(f".pystandalone file has no entrypoint {run_entry}")

        self.run = spec.get(run_entry, "entry")
        self.base = path.parent.resolve()

        if not self.base.joinpath(self.run).is_file():
            # If the run entry is not a file, it must be an entry point string like module:func
            if self.run.count(":") != 1:
                raise ValueError(f"Run entry is not an existing file or a valid entrypoint string: {self.run}")
            entry_module, _, _ = self.run.partition(":")
            self.modules.add(entry_module.split(".")[0])

        if "library" in spec:
            self.library.update(set(spec.options("library")))

        if "modules" in spec:
            self.modules.update(set(spec.options("modules")))

        if "include" in spec:
            self.include.update(set(spec.options("include")))

        if "exclude" in spec:
            self.exclude.update(set(spec.options("exclude")))

        for name, section in spec.items():
            if name.startswith("build:"):
                _, _, module_name = name.partition(":")
                self.build[module_name] = dict(section.items())

    def insert_file(self, path: str, file: Path) -> None:
        """Insert a file into the source.

        Args:
            path: The path where the file should be inserted.
            file: The file to be inserted.
        """
        self.insert[path] = file.read_text()

    def insert_str(self, path: str, code: str) -> None:
        """Insert a string of code into the source.

        Args:
            path: The path where the code should be inserted.
            code: The string of code to be inserted.
        """
        self.insert[path] = code

    def pack(self) -> Iterator[tuple[str, str | bytes]]:
        """Pack the source code into an iterable of file paths and contents."""
        re_excl = _re_from_set(self.exclude)
        re_incl = _re_from_set(self.include)

        for path, content in self._pack():
            if re_excl and re_excl.match(path) and not (re_incl and re_incl.match(path)):
                continue

            yield path, content

    def _pack(self) -> Iterator[tuple[str, str | bytes]]:
        """Pack the source code into an iterable of file paths and contents."""
        if self.run.endswith(".zip"):
            log.info("Packing from existing zip file %s", self.run)
            yield from pack_zip(self.base.joinpath(self.run))

        else:
            if (run_file := self.base.joinpath(self.run)).is_file():
                log.info("Packing existing run file %s", run_file)
                yield "run.py", run_file.read_text()
            else:
                entry_module, _, entry_func = self.run.partition(":")
                log.info("Creating and packing run file for %s", entry_module)
                yield "run.py", RUN_MODULE_TEMPLATE.format(entry_module, entry_func.split(".")[0], entry_func)

            if self.include_base:
                log.info("Packing base files from %s", self.base)
                yield from self._pack_base()

            if self.modules:
                log.info("Packing %d modules", len(self.modules))
                yield from self._pack_modules()

        if self.insert:
            log.info("Packing %d inserted files", len(self.insert))
            yield from self.insert.items()

    def _pack_base(self) -> Iterator[tuple[str, str | bytes]]:
        """Pack the base files from the source directory."""
        run_file = self.base.joinpath(self.run)

        for entry in self.base.rglob("*"):
            # If an entry is not a file or a separately packed run file
            if not entry.is_file() or entry.samefile(run_file):
                continue

            yield str(entry.relative_to(self.base)).replace("\\", "/"), entry.read_bytes()

    def _pack_modules(self) -> Iterator[tuple[str, str | bytes]]:
        """Pack the specified modules."""
        for module in self.modules:
            log.info("Packing module '%s'", module)
            yield from self._pack_module(module)

    def _pack_module(self, module: str) -> Iterator[tuple[str, str | bytes]]:
        """Pack a single module."""
        if (spec := importlib.util.find_spec(module)) is None:
            raise ValueError(f"Module {module} not found")

        if module in self.build:
            # This module has a build step, but we need to find an appropriate base directory
            # to run the build step from
            base = _find_module_base_path(spec)

            if base is None:
                log.warning(
                    "Skipping build command for module '%s': unable to find a unique base directory for the module",
                    module,
                )
            else:
                log.info("Running build command for module '%s' from base '%s'", module, base)
                yield from self._pack_build_output(module, base)

        yield from _pack_module(spec)

    def _pack_build_output(self, module: str, base: Path) -> Iterator[tuple[str, str | bytes]]:
        """Run the build command for a module and pack its output."""
        log.info('Running build steps for module "%s"', module)

        for path, command in self.build[module].items():
            log.info("Building '%s' from '%s'", path, command)
            result = subprocess.run(command, shell=True, cwd=base, capture_output=True)

            if result.returncode != 0:
                raise RuntimeError(
                    f'Build command for module "{module}" failed with exit code {result.returncode}:\n'
                    f"stdout:\n{result.stdout.decode()}\n"
                    f"stderr:\n{result.stderr.decode()}"
                )

            yield path, result.stdout


def pack_zip(zip: Path | bytes | BinaryIO) -> Iterator[tuple[str, str | bytes]]:
    if isinstance(zip, bytes):
        zip = io.BytesIO(zip)

    with zipfile.ZipFile(zip) as zipf:
        for zipinfo in zipf.infolist():
            if not zipinfo.is_dir():
                yield zipinfo.filename, zipf.read(zipinfo)


def pack_module(name: str) -> Iterator[tuple[str, str | bytes]]:
    """Pack a module by name into an iterable of file paths and contents."""
    if (spec := importlib.util.find_spec(name)) is None:
        raise ValueError(f"Module {name} not found")

    yield from _pack_module(spec)


def _pack_module(spec: ModuleSpec) -> Iterator[tuple[str, str | bytes]]:
    for base_path, full_path in _iter_module_files(spec):
        yield str(full_path.relative_to(base_path)).replace("\\", "/"), full_path.read_bytes()

    if (not spec.origin and len(spec.submodule_search_locations)) or (
        spec.origin and spec.origin.endswith("__init__.py")
    ):
        # Fill in missing __init__.py files for namespace packages
        relative_path = ""
        for part in spec.name.split("."):
            relative_path = "/".join([relative_path, part]) if relative_path else part  # noqa: FLY002
            yield f"{relative_path}/__init__.py", b""


def _iter_module_files(spec: ModuleSpec) -> Iterator[tuple[Path, str]]:
    """Iterate over the files in a module specified by a ModuleSpec."""
    if not spec.submodule_search_locations and spec.origin:
        # Single file modules, so base path must be site-packages
        yield _get_module_base_path(spec.name, spec.origin), spec.origin

    else:
        # Normal and namespace modules
        for search_path in spec.submodule_search_locations:
            search_path = Path(search_path)
            base = _get_module_base_path(spec.name, search_path)

            for root, dirs, files in os.walk(search_path):
                if "__pycache__" in dirs:
                    dirs.remove("__pycache__")

                for file in files:
                    # ignore .pyc files if we have .py originals
                    if file.endswith(".pyc") and file[:-1] in files:
                        continue

                    yield base, Path(root).joinpath(file)


def _find_module_base_path(spec: ModuleSpec) -> Path | None:
    if spec.origin:
        # This covers things like dissect.target and other regular packages, which will
        # have an origin of package/name/__init__.py
        return _get_module_base_path(spec.name, Path(spec.origin))

    if len(spec.submodule_search_locations) == 1:
        # This covers namespace packages that don't have an __init__.py
        return _get_module_base_path(spec.name, Path(spec.submodule_search_locations[0]))

    return None


def _get_module_base_path(name: str, path: Path) -> Path:
    # Namespaced packages end in site-packages/name/space/
    # Module packages end in site-packages/module
    # Single file packages end in site-packages/
    # E.g. /site-packages/dissect/target/__init__.py -> /site-packages/
    # E.g. /site-packages/acquire -> /site-packages/
    # E.g. /site-packages/six.py -> /site-packages/
    base = path.parent if path.is_file() else path
    if path.name == "__init__.py" or path.is_dir():
        for _ in name.split("."):
            base = base.parent

    return base


def _re_from_set(s: set[str]) -> re.Pattern | None:
    return re.compile("|".join([fnmatch.translate(e) for e in s])) if s else None
