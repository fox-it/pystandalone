from __future__ import annotations

import importlib.resources
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator

BOOTSTRAP_TEMPLATE = """
import runpy
import sys
import zipimport

import _pystandalone

payload = _pystandalone.get_payload()

{decrypt}

payload_importer = zipimport.metazipimporter('<payload>', payload)
{importer}

# Monkey patch some stuff
import monkey

runpy._run_module_as_main("run", alter_argv=False)
"""

NO_CRYPT_TEMPLATE = """
import hashlib

DIGEST = {digest!r}

if hashlib.sha256(payload).digest() != DIGEST:
    sys.exit("ERROR: Wrong key")
"""

DECRYPT_TEMPLATE = """
import hashlib
from argparse import ArgumentParser
from os import environ

DIGEST = {digest!r}
IV = {iv!r}

parser = ArgumentParser(prefix_chars=':')
parser.add_argument(":key", default=environ.get("PYSTANDALONE_KEY"), required=False)
known, remainder = parser.parse_known_args()

if known.key:
    key = known.key.encode()
    environ["PYSTANDALONE_KEY_SOURCE"] = "args"
    sys.argv = [sys.argv[0]] + remainder
else:
    environ["PYSTANDALONE_KEY_SOURCE"] = "prompt"
    try:
        from wingui import KeyGUI
        key = KeyGUI.prompt("Please enter key").encode()
    except ImportError:
        import getpass
        key = getpass.getpass("Key: ").encode()

cipher = _pystandalone.chacha20(hashlib.sha256(key).digest(), IV)
payload = cipher.decrypt(payload)
cipher.clean()
if hashlib.sha256(payload).digest() != DIGEST:
    sys.exit("ERROR: Wrong key")
"""

FILESYSTEM_IMPORTER_TEMPLATE = """
# Insert before the filesystem importer
sys.meta_path.insert(len(sys.meta_path) - 1, payload_importer)
"""

NO_FILESYSTEM_IMPORTER_TEMPLATE = """
# Remove the filesystem importer and add payload importer
sys.meta_path.pop()
sys.meta_path.append(payload_importer)
"""


class Bootstrap:
    def __init__(
        self,
        digest: str,
        encrypt: bool = True,
        iv: bytes | None = None,
        filesystem_importer: bool = False,
    ):
        self.digest = digest
        self.encrypt = encrypt
        self.iv = iv
        self.filesystem_importer = filesystem_importer

    def pack(self) -> Iterator[tuple[str, str | bytes]]:
        bootstrap = BOOTSTRAP_TEMPLATE.format(
            decrypt=self._decrypt_stub(),
            importer=self._filesystem_stub(),
        )

        yield "bootstrap.py", bootstrap
        yield "wingui.py", importlib.resources.read_text("pystandalone.redist", "wingui.py")
        yield "monkey.py", importlib.resources.read_text("pystandalone.redist", "monkey.py")

    def _decrypt_stub(self) -> str:
        if self.encrypt:
            return DECRYPT_TEMPLATE.format(digest=self.digest, iv=self.iv)
        return NO_CRYPT_TEMPLATE.format(digest=self.digest)

    def _filesystem_stub(self) -> str:
        if self.filesystem_importer:
            return FILESYSTEM_IMPORTER_TEMPLATE
        return NO_FILESYSTEM_IMPORTER_TEMPLATE
