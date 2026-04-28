from __future__ import annotations

import argparse
import hashlib
import importlib.resources
import itertools
import logging
import os
import sys
from pathlib import Path

from pystandalone import chacha20
from pystandalone.compiler import CryptCompiler, NoCompiler
from pystandalone.packer import Packer
from pystandalone.source import Source, pack_module, pack_zip

log = logging.getLogger(__name__)
logging.lastResort = None
logging.raiseExceptions = False

BOOTSTRAP_SENTINEL = b"Kusjes van SRT!"

BOOTSTRAP_STANDALONE_TEMPLATE = """
import runpy
import sys

{decrypt}

runpy._run_module_as_main("run", alter_argv=False)
"""

DECRYPT_TEMPLATE = f"""
import hashlib
import zipimport
from argparse import ArgumentParser
from os import environ

import chacha20

SENTINEL = {{sentinel!r}}
IV = {{iv!r}}

parser = ArgumentParser(prefix_chars=':')
parser.add_argument(":key", default=environ.get("PYSTANDALONE_KEY"), required=False)
known, remainder = parser.parse_known_args()

if known.key:
    key = known.key
    environ["PYSTANDALONE_KEY_SOURCE"] = "args"
    sys.argv = [sys.argv[0]] + remainder
else:
    environ["PYSTANDALONE_KEY_SOURCE"] = "prompt"
    try:
        from wingui import KeyGUI
        key = KeyGUI.prompt("Please enter key")
    except ImportError:
        import getpass
        key = getpass.getpass("Key: ")

key = hashlib.sha256(key.encode()).digest()

if chacha20.decrypt(SENTINEL, key, IV) != {BOOTSTRAP_SENTINEL!r}:
    sys.exit("ERROR: Wrong key")

_get_data = zipimport._get_data
def get_data(archive, toc_entry):
    buf = _get_data(archive, toc_entry)
    return chacha20.decrypt(buf, key, IV)
zipimport._get_data = get_data
"""

BOOTSTRAP_WRAP_TEMPLATE = """
import platform
import os
import sys
import zipfile
from pathlib import Path

from dissect.executable.elf.tools import loader

with zipfile.ZipFile(Path(__file__).parent) as zip:
    with zip.open("exe") as fh:
        loader.load(
            fh,
            argv=sys.argv,
            env=os.environ,
            libc="/lib64/libc.so.6" if platform.system().lower() == "vmkernel" else None
        )
"""


class Builder:
    def __init__(self, code: Path, *, encrypt: bool = True, key: str | None = None):
        self.code = code
        self.encrypt = encrypt

        self.key, self.iv = None, None
        if self.encrypt:
            self.key = key if key is not None else os.urandom(32).hex()
            self.iv = os.urandom(16)

        self.source = Source.from_path(code) if code else Source()

    def build(self) -> bytes:
        # Pack the source code first, optionally encrypting it
        if self.encrypt:
            key = hashlib.sha256(self.key.encode()).digest()
            compiler = CryptCompiler(key, self.iv)
            sentinel = chacha20.encrypt(BOOTSTRAP_SENTINEL, key, self.iv)

            decrypt = DECRYPT_TEMPLATE.format(
                sentinel=sentinel,
                iv=self.iv,
            )
        else:
            compiler = NoCompiler()
            sentinel = BOOTSTRAP_SENTINEL
            decrypt = ""

        payload = Packer(compiler).pack(self.source.pack())

        return Packer().pack(
            (
                (
                    "__main__.py",
                    BOOTSTRAP_STANDALONE_TEMPLATE.format(decrypt=decrypt),
                ),
                ("chacha20.py", importlib.resources.read_text("pystandalone", "chacha20.py")),
                ("wingui.py", importlib.resources.read_text("pystandalone.redist", "wingui.py")),
                # Include the packed source code plainly
                *(pack_zip(payload)),
            )
        )


def wrap(exe: bytes) -> bytes:
    """Wrap the given executable in a zipapp with a bootstrap ELF loader.

    Args:
        exe: The executable to wrap.
    """
    return Packer().pack(
        itertools.chain(
            [
                ("__main__.py", BOOTSTRAP_WRAP_TEMPLATE),
                ("exe", exe),
            ],
            *[
                pack_module(module)
                for module in [
                    "dissect.cstruct",
                    "dissect.executable",
                    "dissect.util",
                ]
            ],
        )
    )


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
        prog="pystandalone-zipapp",
        description="Build opinionated standalone Python zipapps",
    )

    parser.add_argument(
        "-c",
        "--code",
        metavar="CODE",
        type=Path,
        help="path to code file or directory (.zip, .py, .pystandalone or directory containing run.py or .pystandalone file), or leave empty to generate a module-only zipapp",  # noqa: E501
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="OUTPUT",
        type=Path,
        help="path to output zipapp",
    )

    packaging_group = parser.add_argument_group("packaging options")
    packaging_group.add_argument(
        "-M",
        "--modules",
        type=str,
        nargs="*",
        help="extra external modules to include",
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
        "-v",
        "--verbose",
        action="count",
        default=3,
        help="increase output verbosity",
    )
    args = parser.parse_args()

    setup_logging(args.verbose)

    log.info("Setting up builder")

    try:
        builder = Builder(
            args.code,
            encrypt=not args.no_crypt,
            key=args.key,
        )
    except Exception as e:
        log.error("Error creating builder: %s. View debug logs for more details.", e)  # noqa: TRY400
        log.debug("Stacktrace:", exc_info=e)
        return 1

    if args.modules:
        builder.source.modules.update(set(args.modules))

    try:
        exe = builder.build()
    except Exception as e:
        log.error("Error building zipapp: %s. View debug logs for more details.", e)  # noqa: TRY400
        log.debug("Stacktrace:", exc_info=e)
        return 1

    if args.output is None:
        args.output = Path()

    if args.output.is_dir():
        args.output = args.output / "pystandalone-zipapp.pyz"

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
