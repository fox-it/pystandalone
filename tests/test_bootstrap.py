from __future__ import annotations

import os
import subprocess
import sys
import textwrap

from pystandalone.bootstrap import DECRYPT_TEMPLATE, Bootstrap


def test_bootstrap_pack_no_encrypt() -> None:
    """Test that bootstrap without encryption uses the no-crypt template."""
    b = Bootstrap(digest=b"\x00" * 32, encrypt=False)
    packed = dict(b.pack())

    assert "bootstrap.py" in packed
    assert len(packed["bootstrap.py"]) > 0
    assert "monkey.py" in packed
    assert len(packed["monkey.py"]) > 0
    assert "wingui.py" in packed
    assert len(packed["wingui.py"]) > 0
    assert "DIGEST" in packed["bootstrap.py"]
    assert "cipher" not in packed["bootstrap.py"]


def test_bootstrap_pack_encrypt() -> None:
    """Test that bootstrap with encryption uses the decrypt template."""
    b = Bootstrap(digest=b"\x00" * 32, encrypt=True, iv=b"\x01" * 8)
    packed = dict(b.pack())

    assert "chacha20" in packed["bootstrap.py"]
    assert "DIGEST" in packed["bootstrap.py"]
    assert repr(b"\x01" * 8) in packed["bootstrap.py"]


def test_bootstrap_filesystem_importer() -> None:
    """Test that filesystem_importer=True inserts before the filesystem importer."""
    b = Bootstrap(digest=b"\x00" * 32, encrypt=False, filesystem_importer=True)
    packed = dict(b.pack())

    assert "Insert before the filesystem importer" in packed["bootstrap.py"]
    assert "Remove the filesystem importer" not in packed["bootstrap.py"]


def test_bootstrap_no_filesystem_importer() -> None:
    """Test that filesystem_importer=False removes the filesystem importer."""
    b = Bootstrap(digest=b"\x00" * 32, encrypt=False, filesystem_importer=False)
    packed = dict(b.pack())

    assert "Remove the filesystem importer" in packed["bootstrap.py"]
    assert "Insert before the filesystem importer" not in packed["bootstrap.py"]


def test_decrypt_stub_contains_iv() -> None:
    """Test that the decrypt stub contains the IV and digest."""
    b = Bootstrap(digest=b"\xaa" * 32, encrypt=True, iv=b"\xbb" * 8)
    stub = b._decrypt_stub()

    assert repr(b"\xaa" * 32) in stub
    assert repr(b"\xbb" * 8) in stub
    assert "chacha20" in stub


def test_no_crypt_stub_contains_digest() -> None:
    """Test that the no-crypt stub contains the digest but no decryption."""
    b = Bootstrap(digest=b"\xcc" * 32, encrypt=False)
    stub = b._decrypt_stub()

    assert repr(b"\xcc" * 32) in stub
    assert "chacha20" not in stub


def test_generated_bootstrap_compiles() -> None:
    """Test that all generated bootstrap variants produce valid Python syntax."""
    for encrypt in (True, False):
        for fs_importer in (True, False):
            b = Bootstrap(
                digest=b"\x00" * 32,
                encrypt=encrypt,
                iv=b"\x00" * 8 if encrypt else None,
                filesystem_importer=fs_importer,
            )
            packed = dict(b.pack())
            for name, code in packed.items():
                compile(code, name, "exec")


def _run_key_script(args: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    """Run a script that exercises the key parsing logic from DECRYPT_TEMPLATE."""
    # Build a minimal script that sets up the required globals, runs the key parsing
    # portion of the decrypt template, and prints the result.
    decrypt_code = DECRYPT_TEMPLATE.format(digest=b"\x00" * 32, iv=b"\x00" * 8)

    # Extract just the key parsing logic (everything up to the cipher usage)
    lines = decrypt_code.strip().splitlines()
    key_lines = []
    for line in lines:
        if "cipher" in line or "_pystandalone" in line:
            break
        key_lines.append(line)

    script = textwrap.dedent("""\
        import sys
        sys.argv = ["test"] + {args!r}
        {key_code}
        print(repr(key))
    """).format(args=args, key_code="\n".join(key_lines))

    return subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        env=env,
    )


def test_key_from_args_hex() -> None:
    """Test that hex keys are handled correctly."""
    hex_key = "aa" * 32
    result = _run_key_script([":key", hex_key])

    assert result.returncode == 0
    assert repr(hex_key) in result.stdout


def test_key_from_args_raw() -> None:
    """Test that a non-hex keys are handled correctly."""
    result = _run_key_script([":key", "mypassword"])

    assert result.returncode == 0
    assert repr(b"mypassword") in result.stdout


def test_key_from_args_equals() -> None:
    """Test that :key=VALUE syntax works."""
    result = _run_key_script([":key=secretkey"])

    assert result.returncode == 0
    assert repr(b"secretkey") in result.stdout


def test_key_from_env() -> None:
    """Test that the key is read from PYSTANDALONE_KEY environment variable."""
    env = {**os.environ, "PYSTANDALONE_KEY": "envkey"}
    result = _run_key_script([], env=env)

    assert result.returncode == 0
    assert repr(b"envkey") in result.stdout
