from __future__ import annotations

import os
import subprocess
import sys
import zipfile
from typing import TYPE_CHECKING

from pystandalone.zipapp import Builder, main

if TYPE_CHECKING:
    from pathlib import Path

    import pytest


def _build_and_run(
    tmp_path: Path,
    code: str,
    *,
    encrypt: bool = True,
    encrypt_key: str | None = None,
    decrypt_key: str | None = None,
    decrypt_key_env: bool = False,
    args: list[str] | None = None,
) -> subprocess.CompletedProcess:
    run = tmp_path / "run.py"
    run.write_text(code)

    builder = Builder(run, encrypt=encrypt, key=encrypt_key)
    pyz = tmp_path / "app.pyz"
    pyz.write_bytes(builder.build())

    key = decrypt_key if decrypt_key is not None else builder.key

    cmd = [sys.executable, str(pyz)]
    if encrypt and not decrypt_key_env:
        cmd.append(f":key={key}")

    if args:
        cmd.extend(args)

    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"

    if encrypt and decrypt_key_env:
        env["PYSTANDALONE_KEY"] = key

    return subprocess.run(cmd, capture_output=True, timeout=30, env=env)


def test_zipapp_hello_world(tmp_path: Path) -> None:
    """Test that a simple unencrypted zipapp runs and produces expected output."""
    result = _build_and_run(
        tmp_path,
        "print('hello from zipapp', flush=True)",
        encrypt=False,
    )

    assert result.returncode == 0
    assert b"hello from zipapp" in result.stdout


def test_zipapp_encrypted(tmp_path: Path) -> None:
    """Test that an encrypted zipapp runs with the correct key."""
    result = _build_and_run(
        tmp_path,
        "print('encrypted zipapp', flush=True)",
        encrypt=True,
        encrypt_key="testkey123",
    )

    assert result.returncode == 0
    assert b"encrypted zipapp" in result.stdout


def test_zipapp_encrypted_wrong_key(tmp_path: Path) -> None:
    """Test that an encrypted zipapp fails with a wrong key."""
    result = _build_and_run(
        tmp_path,
        "print('should not see this')",
        encrypt=True,
        encrypt_key="correctkey",
        decrypt_key="wrongkey",
    )

    assert result.returncode != 0
    assert b"Wrong key" in result.stderr


def test_zipapp_encrypted_key_from_env(tmp_path: Path) -> None:
    """Test that the encryption key can be passed via environment variable."""
    result = _build_and_run(
        tmp_path,
        "print('env key works', flush=True)",
        encrypt=True,
        encrypt_key="envkey123",
        decrypt_key_env=True,
    )

    assert result.returncode == 0
    assert b"env key works" in result.stdout


def test_zipapp_exit_code(tmp_path: Path) -> None:
    """Test that the exit code from the script is propagated."""
    result = _build_and_run(tmp_path, "import sys; sys.exit(42)", encrypt=False)
    assert result.returncode == 42


def test_zipapp_argv_passthrough(tmp_path: Path) -> None:
    """Test that command-line arguments are passed through to the script."""
    result = _build_and_run(
        tmp_path,
        "import sys; print(' '.join(sys.argv[1:]), flush=True)",
        encrypt=False,
        args=["foo", "bar"],
    )

    assert result.returncode == 0
    assert b"foo bar" in result.stdout


def test_zipapp_argv_passthrough_encrypted(tmp_path: Path) -> None:
    """Test that command-line arguments are passed through and :key is stripped."""
    result = _build_and_run(
        tmp_path,
        "import sys; print(' '.join(sys.argv[1:]), flush=True)",
        encrypt=True,
        encrypt_key="argkey",
        args=["--flag", "value"],
    )

    assert result.returncode == 0
    assert b"--flag value" in result.stdout
    assert b":key" not in result.stdout


def test_zipapp_stderr(tmp_path: Path) -> None:
    """Test that stderr output from the script is captured."""
    result = _build_and_run(
        tmp_path,
        "import sys; print('error msg', file=sys.stderr)",
        encrypt=False,
    )

    assert result.returncode == 0
    assert b"error msg" in result.stderr


def test_zipapp_import_stdlib(tmp_path: Path) -> None:
    """Test that stdlib modules can be imported and used."""
    result = _build_and_run(
        tmp_path,
        "import json; print(json.dumps({'key': 'value'}), flush=True)",
        encrypt=False,
    )

    assert result.returncode == 0
    assert b'{"key": "value"}' in result.stdout


def test_main_with_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that main with a key produces an encrypted output."""
    code = tmp_path / "run.py"
    code.write_text("pass")

    output = tmp_path / "out.pyz"

    monkeypatch.setattr("sys.argv", ["pystandalone-zipapp", "-c", str(code), "-o", str(output), "-k", "mykey"])

    result = main()

    assert result == 0
    assert output.exists()
    assert output.stat().st_size > 0

    zf = zipfile.ZipFile(output)
    assert "__main__.py" in zf.namelist()


def test_main_with_key_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that main writes the key to a file when --key-file is used."""
    code = tmp_path / "run.py"
    code.write_text("pass")

    output = tmp_path / "out.pyz"
    key_file = tmp_path / "key.txt"

    monkeypatch.setattr(
        "sys.argv",
        ["pystandalone-zipapp", "-c", str(code), "-o", str(output), "-k", "savedkey", "--key-file", str(key_file)],
    )

    result = main()

    assert result == 0
    assert key_file.exists()
    assert key_file.read_text() == "savedkey"


def test_main_default_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that main uses default output path when -o is not specified."""
    code = tmp_path / "run.py"
    code.write_text("pass")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("sys.argv", ["pystandalone-zipapp", "-c", str(code), "-k", "testkey"])

    result = main()

    assert result == 0
    assert (tmp_path / "pystandalone-zipapp.pyz").exists()


def test_main_invalid_code_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that main returns 1 for an empty directory with no run.py."""
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()

    monkeypatch.setattr("sys.argv", ["pystandalone-zipapp", "-c", str(empty_dir)])

    result = main()

    assert result == 1
