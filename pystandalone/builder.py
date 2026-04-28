from __future__ import annotations

import argparse
import hashlib
import logging
import os
import sys
from pathlib import Path

from pystandalone import binary, chacha20, zipapp
from pystandalone.bootstrap import Bootstrap
from pystandalone.compiler import NoCompiler, PycCompiler
from pystandalone.distribution import (
    Architecture,
    Distribution,
    Target,
    get_distribution_map,
)
from pystandalone.packer import Packer
from pystandalone.source import Source

log = logging.getLogger(__name__)
logging.lastResort = None
logging.raiseExceptions = False

DISTRIBUTIONS = get_distribution_map()


class Builder:
    """Pystandalone executable builder.

    Args:
        distribution: The distribution to build for.
        code: The path to the source code to include in the payload
            (can be a .py file, a .zip file, a .pystandalone spec file, or a directory containing a
            .pystandalone spec file or a run.py file). If None, only the library will be included in the binary.
        encrypt: Whether to encrypt the payload zip.
        key: The encryption key to use (if None, a random key will be generated).
        extra: Extra Python code to insert in the bootstrap.
        compile: Whether to compile .py files to .pyc in the payload zip
            (NOTE: requires you run pystandalone with the same Python version as the target binary).
        strict: Whether totreat a mismatch in bytecode magic number as an error when compiling.
        filesystem_importer: Whether to include the filesystem importer in the bootstrap.
    """

    def __init__(
        self,
        distribution: Distribution,
        code: Path | None = None,
        *,
        encrypt: bool = True,
        key: str | None = None,
        compile: bool = True,
        strict: bool = True,
        filesystem_importer: bool = False,
    ):
        self.distribution = distribution
        self.code = code

        self.encrypt = self.code is not None and encrypt

        self.filesystem_importer = filesystem_importer
        self.strict = strict

        self.key, self.iv = None, None
        if self.encrypt:
            self.key = key if key is not None else os.urandom(32).hex()
            self.iv = os.urandom(16)
        elif self.code:
            log.warning("NOT encrypting payload zip!")

        self.strict = strict

        self.source = Source.from_path(code) if code else Source()

        compiler = PycCompiler(self.distribution.bytecode_magic, strict=self.strict) if compile else NoCompiler()
        self.packer = Packer(compiler)

    def add_library(self, name: str) -> None:
        """Add a library module to include in the binary.

        Args:
            name: The name of the library module to include (e.g. "argparse").
        """
        self.source.library.add(name)

    def add_module(self, name: str) -> None:
        """Add a module to include in the binary.

        Args:
            name: The name of the module to include (e.g. "requests").
        """
        self.source.modules.add(name)

    def add_source_file(self, path: str, file: Path) -> None:
        """Add a source file to include in the payload zip.

        Args:
            path: The path to the file in the payload zip.
            file: The path to the source file to include.
        """
        self.source.insert_file(path, file)

    def add_source_str(self, path: str, code: str) -> None:
        """Add a source string to include in the payload zip.

        Args:
            path: The path to the file in the payload zip.
            code: The source code to include.
        """
        self.source.insert_str(path, code)

    def encrypt_payload(self, payload: bytes) -> bytes:
        """Encrypt the payload with the builder's key and iv."""
        return chacha20.encrypt(payload, hashlib.sha256(self.key.encode()).digest(), self.iv)

    def build_library_zip(self) -> bytes:
        """Build the library zip."""
        log.info("Packing library (include: %s)", ", ".join(self.source.library))
        return self.packer.pack(self.distribution.pack_library(self.source.library))

    def build_bootstrap_zip(self, digest: bytes) -> bytes:
        """Build the bootstrap zip.

        Args:
            digest: The digest of the payload zip, for the bootstrap to verify integrity.
        """
        bootstrap = Bootstrap(
            digest=digest,
            encrypt=self.encrypt,
            iv=self.iv,
            filesystem_importer=self.filesystem_importer,
        )

        return self.packer.pack(bootstrap.pack())

    def build_payload_zip(self) -> bytes:
        """Build the payload zip."""
        log.info("Packing payload from %s", self.source.run)
        return self.packer.pack(self.source.pack())

    def build_payload_bin(self, zips: list[bytes]) -> bytes:
        """Build the payload binary blob.

        Args:
            zips: A list of zip files to include in the payload binary.
        """
        return binary.pack_zip(zips)

    def build_exe(self, payload: bytes) -> bytes:
        """Build the final executable binary.

        Args:
            payload: The payload binary blob to patch into the executable.
        """
        return binary.patch(self.distribution, payload)

    def _dump_artefact(self, path: Path | None, name: str, buf: bytes) -> None:
        """Dump an artefact to disk for debugging purposes.

        Args:
            path: The directory path to dump the artefact.
            name: The name of the artefact file.
            buf: The bytes content of the artefact to write.
        """
        if path is None:
            return

        if not path.exists():
            path.mkdir(parents=True, exist_ok=True)

        out_path = path.joinpath(name)
        log.debug("Writing %s", out_path)
        out_path.write_bytes(buf)

    def build(self, *, build_path: Path | None) -> bytes:
        """Build the standalone executable binary.

        Args:
            build_path: A directory path to dump the artefacts for debugging purposes.

        Returns:
            The bytes of the standalone executable binary.
        """
        library_zip = self.build_library_zip()
        self._dump_artefact(build_path, "library.zip", library_zip)

        zips = [library_zip]

        if self.source.run:
            payload_zip = self.build_payload_zip()
            self._dump_artefact(build_path, "payload.zip", payload_zip)

            payload_digest = hashlib.sha256(payload_zip).digest()

            if self.encrypt:
                log.info("Encrypting payload zip")
                payload_zip = self.encrypt_payload(payload_zip)
                self._dump_artefact(build_path, "payload.bin", payload_zip)

            log.info("Packing bootstrap code")
            bootstrap_zip = self.build_bootstrap_zip(payload_digest)
            self._dump_artefact(build_path, "bootstrap.zip", bootstrap_zip)

            zips.append(bootstrap_zip)
            zips.append(payload_zip)
        else:
            log.info("No code payload given, building library only binary")

        standalone_payload = self.build_payload_bin(zips)
        self._dump_artefact(build_path, "standalone.bin", standalone_payload)

        exe = self.build_exe(standalone_payload)
        self._dump_artefact(build_path, "standalone.exe", exe)
        return exe


def select_distribution(python: str, target: Target | None, arch: Architecture | None) -> Distribution | None:
    if target is None:
        try:
            target = Target.from_current()
        except RuntimeError:
            log.error("Unsupported platform for auto-detection. Please specify target with --target.")  # noqa: TRY400
            return None
        log.warning("Derived target from current system: %s", target.value)

    if arch is None:
        try:
            arch = Architecture.from_current()
        except RuntimeError:
            log.error("Unsupported architecture for auto-detection. Please specify architecture with --arch.")  # noqa: TRY400
            return None
        log.warning("Derived architecture from current system: %s", arch.value)

    if python not in DISTRIBUTIONS:
        log.error("No distribution available for Python %s", python)
        return None

    if target not in DISTRIBUTIONS[python]:
        log.error("No distribution available for Python %s and target %s", python, target.value)
        return None

    if arch not in DISTRIBUTIONS[python][target]:
        log.error(
            "No distribution available for Python %s, target %s and architecture %s",
            python,
            target.value,
            arch.value,
        )
        return None

    return DISTRIBUTIONS[python][target][arch].get(progress=True)


def setup_logging(verbosity: int) -> None:
    """Set up logging with the given verbosity level.

    Args:
        verbosity: The verbosity level (0 for critical, 1 for error, 2 for warning, 3 for info, 4 or higher for debug).
    """
    if verbosity == 1:
        level = logging.ERROR
    elif verbosity == 2:
        level = logging.WARNING
    elif verbosity == 3:
        level = logging.INFO
    elif verbosity >= 4:
        level = logging.DEBUG
    else:
        level = logging.CRITICAL

    logging.basicConfig(format="%(levelname)s %(message)s", level=level)

    logging.addLevelName(logging.DEBUG, " - ")
    logging.addLevelName(logging.INFO, "[*]")

    for lvl in [logging.WARNING, logging.ERROR, logging.CRITICAL]:
        logging.addLevelName(lvl, "[!]")


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="pystandalone",
        description="Build opinionated standalone Python executables",
    )

    parser.add_argument(
        "-c",
        "--code",
        metavar="CODE",
        type=Path,
        help="path to code file or directory (.zip, .py, .pystandalone or directory containing run.py or .pystandalone file), or leave empty to generate a library-only binary",  # noqa: E501
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="OUTPUT",
        type=Path,
        help="path to output binary",
    )

    distribution_group = parser.add_argument_group("distribution options")
    distribution_group.add_argument(
        "-p",
        "--python",
        metavar="PYTHON",
        default="3.10",
        choices=DISTRIBUTIONS.keys(),
        help="version of Python to build a binary for (default: %(default)s, available: %(choices)s)",
    )
    distribution_group.add_argument(
        "-t",
        "--target",
        metavar="TARGET",
        type=Target,
        default=None,
        choices=Target.__members__.values(),
        help="target OS binary (default: autodetect, available: %(choices)s)",
    )
    distribution_group.add_argument(
        "-a",
        "--arch",
        metavar="ARCH",
        type=Architecture,
        default=None,
        choices=Architecture.__members__.values(),
        help="target architecture (default: autodetect based on target, available: %(choices)s)",
    )
    distribution_group.add_argument(
        "-d",
        "--distribution",
        metavar="DISTRIBUTION",
        type=Path,
        help="path to custom pystandalone distribution (overrides target and arch)",
    )
    distribution_group.add_argument(
        "--list-available",
        action="store_true",
        help="list available distributions and exit",
    )

    packaging_group = parser.add_argument_group("packaging options")
    packaging_group.add_argument(
        "-L",
        "--library",
        type=str,
        nargs="*",
        help="extra library modules to include",
    )
    packaging_group.add_argument(
        "-M",
        "--modules",
        type=str,
        nargs="*",
        help="extra external modules to include",
    )
    packaging_group.add_argument(
        "--compile",
        action="store_true",
        help="compile .py files to .pyc in the payload zip (NOTE: requires you run pystandalone with the same Python version as the target binary",  # noqa: E501
    )
    packaging_group.add_argument(
        "--filesystem-importer",
        action="store_true",
        help="add the filesystem importer",
    )
    packaging_group.add_argument(
        "--no-strict",
        action="store_true",
        default=False,
        help=argparse.SUPPRESS,
    )

    packaging_group.add_argument(
        "--zipapp",
        "--pyz",
        action="store_true",
        help="wrap the binary in a zipapp with a bootstrap ELF loader (Linux x86_64 and aarch64 only)",
    )

    encryption_group = parser.add_argument_group("encryption options")
    encryption_group.add_argument(
        "-k",
        "--key",
        type=str,
        help="use provided key for encryption",
    )
    encryption_group.add_argument(
        "--key-file",
        type=Path,
        help="write encryption key to file",
    )
    encryption_group.add_argument(
        "--no-crypt",
        action="store_true",
        default=False,
        help="disable encryption",
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="dump intermediary files",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=3,
        help="increase output verbosity",
    )
    args = parser.parse_args()

    if args.debug:
        args.verbose = 5
    setup_logging(args.verbose)

    if args.list_available:
        for version, targets in DISTRIBUTIONS.items():
            print(f"Python {version}:")

            if args.verbose <= 3:
                for target, archs in sorted(targets.items(), key=lambda item: item[0].value):
                    archs_str = ", ".join(arch.value for arch in sorted(archs, key=lambda item: item.value))
                    print(f"  {target.value}: {archs_str}")
            else:
                for _, archs in sorted(targets.items(), key=lambda item: item[0].value):
                    for _, dist in sorted(archs.items(), key=lambda item: item[0].value):
                        if args.verbose >= 5:
                            print(f"  {dist.target_triple}: {dist.url} (digest: {dist.digest})")
                        else:
                            print(f"  {dist.target_triple}")
        return 0

    if args.distribution:
        distribution = Distribution(args.distribution)
        args.target = distribution.target
        args.arch = distribution.arch

        log.info(
            "Using custom distribution from %s (target: %s, arch: %s)",
            args.distribution,
            distribution.target.value,
            distribution.arch.value,
        )
    else:
        if (distribution := select_distribution(args.python, args.target, args.arch)) is None:
            return 1

        log.info(
            "Using distribution for Python %s (target: %s, arch: %s)",
            args.python,
            distribution.target.value,
            distribution.arch.value,
        )

    log.info("Setting up builder for %s (%s)", distribution.target.value, distribution.arch.value)

    try:
        builder = Builder(
            distribution,
            args.code,
            encrypt=not args.no_crypt,
            key=args.key,
            compile=args.compile,
            strict=not args.no_strict,
            filesystem_importer=args.filesystem_importer,
        )
    except Exception as e:
        log.error("Error creating builder: %s. View debug logs for more details.", e)  # noqa: TRY400
        log.debug("Stacktrace:", exc_info=e)
        return 1

    if args.library:
        builder.source.library.update(set(args.library))

    if args.modules:
        builder.source.modules.update(set(args.modules))

    try:
        exe = builder.build(build_path=Path("build") if args.debug else None)
    except Exception as e:
        log.error("Error building binary: %s. View debug logs for more details.", e)  # noqa: TRY400
        log.debug("Stacktrace:", exc_info=e)
        return 1

    if args.output is None:
        args.output = Path()

    if args.output.is_dir():
        ext = ".exe" if distribution.target == Target.WINDOWS else ""
        args.output = Path(
            f"pystandalone-{distribution.version}-{distribution.target.value}-{distribution.arch.value}{ext}"
        )

    if args.zipapp:
        if distribution.target != Target.LINUX or distribution.arch not in (Architecture.X86_64, Architecture.AARCH64):
            log.error("zipapp wrapping is only supported on Linux x86_64 and aarch64 targets")
            return 1

        log.info("Wrapping binary in zipapp with bootstrap ELF loader")
        exe = zipapp.wrap(exe)
        args.output = args.output.with_suffix(args.output.suffix + ".pyz")

    log.info("Writing %s", args.output)
    args.output.write_bytes(exe)

    if builder.key:
        log.info("")
        log.info("Key: %s", builder.key)
        if args.key_file:
            log.info("Writing %s", args.key_file)
            args.key_file.write_text(builder.key)

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        pass
