from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import sys
from typing import TYPE_CHECKING

import pytest

from pystandalone import chacha20
from pystandalone.builder import Builder, main, select_distribution
from pystandalone.compiler import NoCompiler, PycCompiler
from pystandalone.distribution import Architecture, Target, get_distribution_map

if TYPE_CHECKING:
    from pathlib import Path

    from pystandalone.distribution import Distribution


def test_builder_init_defaults(linux_distribution: Distribution, tmp_path: Path) -> None:
    """Test that a Builder with code sets up encryption by default."""
    code = tmp_path / "run.py"
    code.write_text("pass")

    builder = Builder(linux_distribution, code, compile=False)

    assert builder.encrypt is True
    assert builder.key is not None
    assert builder.iv is not None
    assert len(builder.iv) == 16


def test_builder_init_compile(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that a Builder with compile=True uses PycCompiler."""
    code = tmp_path / "run.py"
    code.write_text("pass")

    builder = Builder(native_distribution, code, strict=False)

    assert isinstance(builder.packer.compiler, PycCompiler)


def test_builder_init_no_code(linux_distribution: Distribution) -> None:
    """Test that a Builder without code disables encryption."""
    builder = Builder(linux_distribution, compile=False)

    assert builder.encrypt is False
    assert builder.key is None
    assert builder.iv is None
    assert builder.source.run is None


def test_builder_init_no_encrypt(linux_distribution: Distribution, tmp_path: Path) -> None:
    """Test that encryption can be disabled."""
    code = tmp_path / "run.py"
    code.write_text("pass")

    builder = Builder(linux_distribution, code, encrypt=False, compile=False)

    assert builder.encrypt is False
    assert builder.key is None
    assert builder.iv is None


def test_builder_init_custom_key(linux_distribution: Distribution, tmp_path: Path) -> None:
    """Test that a custom encryption key is used when provided."""
    code = tmp_path / "run.py"
    code.write_text("pass")

    builder = Builder(linux_distribution, code, key="mysecretkey", compile=False)

    assert builder.key == "mysecretkey"


def test_builder_init_no_compile(linux_distribution: Distribution, tmp_path: Path) -> None:
    """Test that compilation can be disabled."""
    code = tmp_path / "run.py"
    code.write_text("pass")

    builder = Builder(linux_distribution, code, compile=False)

    assert isinstance(builder.packer.compiler, NoCompiler)


def test_add_library(linux_distribution: Distribution) -> None:
    """Test that add_library adds to the source library set."""
    builder = Builder(linux_distribution, compile=False)
    builder.add_library("json")
    builder.add_library("csv")

    assert "json" in builder.source.library
    assert "csv" in builder.source.library


def test_add_module(linux_distribution: Distribution, tmp_path: Path) -> None:
    """Test that add_module adds to the source modules set."""
    code = tmp_path / "run.py"
    code.write_text("pass")

    builder = Builder(linux_distribution, code, compile=False)
    builder.add_module("requests")

    assert "requests" in builder.source.modules


def test_add_source_str(linux_distribution: Distribution, tmp_path: Path) -> None:
    """Test that add_source_str inserts code into the source."""
    code = tmp_path / "run.py"
    code.write_text("pass")

    builder = Builder(linux_distribution, code, compile=False)
    builder.add_source_str("helper.py", "x = 1")

    packed = dict(builder.source.pack())
    assert packed["helper.py"] == "x = 1"


def test_add_source_file(linux_distribution: Distribution, tmp_path: Path) -> None:
    """Test that add_source_file inserts a file into the source."""
    code = tmp_path / "run.py"
    code.write_text("pass")
    data = tmp_path / "data.txt"
    data.write_text("hello")

    builder = Builder(linux_distribution, code, compile=False)
    builder.add_source_file("extra/data.txt", data)

    packed = dict(builder.source.pack())
    assert packed["extra/data.txt"] == "hello"


def test_encrypt_payload_roundtrip(linux_distribution: Distribution, tmp_path: Path) -> None:
    """Test that encrypting and decrypting payload produces original data."""
    code = tmp_path / "run.py"
    code.write_text("pass")

    builder = Builder(linux_distribution, code, compile=False)
    original = b"test payload data " * 100

    encrypted = builder.encrypt_payload(original)
    assert encrypted != original

    decrypted = chacha20.decrypt(encrypted, hashlib.sha256(builder.key.encode()).digest(), builder.iv)
    assert decrypted == original


def test_build_library_zip(linux_distribution: Distribution) -> None:
    """Test that build_library_zip produces a non-empty zip."""
    builder = Builder(linux_distribution, compile=False)
    result = builder.build_library_zip()

    assert len(result) > 0
    # Should be a valid zip (starts with PK magic)
    assert result[:2] == b"PK"


def test_dump_artefact(linux_distribution: Distribution, tmp_path: Path) -> None:
    """Test that _dump_artefact writes files to the given path."""
    builder = Builder(linux_distribution, compile=False)

    dump_dir = tmp_path / "dump"
    builder._dump_artefact(dump_dir, "test.bin", b"hello")

    assert (dump_dir / "test.bin").read_bytes() == b"hello"


def test_dump_artefact_none(linux_distribution: Distribution) -> None:
    """Test that _dump_artefact with None path is a no-op."""
    builder = Builder(linux_distribution, compile=False)
    builder._dump_artefact(None, "test.bin", b"hello")


def test_select_distribution_valid() -> None:
    """Test that select_distribution returns a distribution for valid inputs."""
    distributions = get_distribution_map()

    # Pick any available version/target/arch combo
    version = next(iter(distributions))
    target = next(iter(distributions[version]))
    arch = next(iter(distributions[version][target]))

    dist = select_distribution(version, target, arch)
    assert dist is not None


def test_select_distribution_invalid_version() -> None:
    """Test that select_distribution raises KeyError for a non-existent version."""
    assert select_distribution("1.0", Target.LINUX, Architecture.X86_64) is None


def test_select_distribution_invalid_arch() -> None:
    """Test that select_distribution returns None for a non-existent arch combo."""
    distributions = get_distribution_map()
    version = next(iter(distributions))

    assert select_distribution(version, Target.MACOS, Architecture.I686) is None


def _build_and_run(
    distribution: Distribution,
    tmp_path: Path,
    code: str,
    *,
    compile: bool = False,
    encrypt: bool = True,
    encrypt_key: str | None = None,
    decrypt_key: str | None = None,
    decrypt_key_env: bool = False,
    args: list[str] | None = None,
) -> subprocess.CompletedProcess:
    run = tmp_path / "run.py"
    run.write_text(code)

    builder = Builder(
        distribution,
        run,
        encrypt=encrypt,
        key=encrypt_key,
        compile=compile,
        strict=True,
    )

    exe = builder.build(build_path=None)
    key = decrypt_key if decrypt_key is not None else builder.key

    out_path = tmp_path / "binary"
    out_path.write_bytes(exe)
    out_path.chmod(out_path.stat().st_mode | stat.S_IEXEC)

    cmd = [str(out_path)]
    if encrypt and not decrypt_key_env:
        cmd.append(f":key={key}")

    if args:
        cmd.extend(args)

    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"

    if encrypt and decrypt_key_env:
        env["PYSTANDALONE_KEY"] = key

    return subprocess.run(cmd, capture_output=True, timeout=30, env=env)


def test_exe_hello_world(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that a simple hello world script runs and produces expected output."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        "print('hello from pystandalone', flush=True)",
        encrypt=False,
    )

    assert result.returncode == 0
    assert b"hello from pystandalone" in result.stdout


def test_exe_compile(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that compiling the code produces a working executable."""
    if native_distribution.major_minor_version != f"{sys.version_info.major}.{sys.version_info.minor}":
        pytest.skip("Can't test compile on a different Python version")

    result = _build_and_run(
        native_distribution,
        tmp_path,
        "print('compiled code works', flush=True)",
        compile=True,
        encrypt=False,
    )

    assert result.returncode == 0
    assert b"compiled code works" in result.stdout


def test_exe_encrypted(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that an encrypted binary runs with the correct key."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        "print('encrypted hello', flush=True)",
        encrypt=True,
        encrypt_key="testkey123",
    )

    assert result.returncode == 0
    assert b"encrypted hello" in result.stdout


def test_exe_encrypted_wrong_key(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that an encrypted binary fails with a wrong key."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        "print('should not see this')",
        encrypt=True,
        encrypt_key="correctkey",
        decrypt_key="wrongkey",
    )

    assert result.returncode != 0
    assert b"Wrong key" in result.stderr


def test_exe_exit_code(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that the exit code from the script is propagated."""
    result = _build_and_run(native_distribution, tmp_path, "import sys; sys.exit(42)", encrypt=False)
    assert result.returncode == 42


def test_exe_argv_passthrough(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that command-line arguments are passed through to the script."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        "import sys; print(' '.join(sys.argv[1:]), flush=True)",
        encrypt=False,
        args=["foo", "bar"],
    )

    assert result.returncode == 0
    assert b"foo bar" in result.stdout


def test_exe_stderr(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that stderr output from the script is captured."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        "import sys; print('error msg', file=sys.stderr)",
        encrypt=False,
    )

    assert result.returncode == 0
    assert b"error msg" in result.stderr


def test_exe_import_stdlib(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that stdlib modules can be imported and used."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        "import json; print(json.dumps({'key': 'value'}), flush=True)",
        encrypt=False,
    )

    assert result.returncode == 0
    assert b'{"key": "value"}' in result.stdout


def test_exe_key_from_env(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that the encryption key can be passed via environment variable."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        "print('env key works', flush=True)",
        encrypt=True,
        encrypt_key="envkey123",
        decrypt_key_env=True,
    )

    assert result.returncode == 0
    assert b"env key works" in result.stdout


def test_main_encrypted(native_distribution: Distribution, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that main produces an encrypted binary that runs."""
    code = tmp_path / "run.py"
    code.write_text("print('main encrypted', flush=True)")

    output = tmp_path / "binary"

    monkeypatch.setattr(
        "sys.argv",
        [
            "pystandalone",
            "-c",
            str(code),
            "-o",
            str(output),
            "-d",
            str(native_distribution.path),
            "-k",
            "mainkey123",
            "--no-strict",
        ],
    )

    assert main() == 0
    assert output.exists()

    output.chmod(output.stat().st_mode | stat.S_IEXEC)
    result = subprocess.run(
        [str(output), ":key=mainkey123"],
        capture_output=True,
        timeout=30,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )

    assert result.returncode == 0
    assert b"main encrypted" in result.stdout


def test_main_no_crypt(native_distribution: Distribution, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that main produces an unencrypted binary that runs."""
    code = tmp_path / "run.py"
    code.write_text("print('main no crypt', flush=True)")

    output = tmp_path / "binary"

    monkeypatch.setattr(
        "sys.argv",
        [
            "pystandalone",
            "-c",
            str(code),
            "-o",
            str(output),
            "-d",
            str(native_distribution.path),
            "--no-crypt",
            "--no-strict",
        ],
    )

    assert main() == 0
    assert output.exists()

    output.chmod(output.stat().st_mode | stat.S_IEXEC)
    result = subprocess.run(
        [str(output)],
        capture_output=True,
        timeout=30,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )

    assert result.returncode == 0
    assert b"main no crypt" in result.stdout


def test_main_key_file(native_distribution: Distribution, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that main writes the key to a file when --key-file is used."""
    code = tmp_path / "run.py"
    code.write_text("pass")

    output = tmp_path / "binary"
    key_file = tmp_path / "key.txt"

    monkeypatch.setattr(
        "sys.argv",
        [
            "pystandalone",
            "-c",
            str(code),
            "-o",
            str(output),
            "-d",
            str(native_distribution.path),
            "-k",
            "savedkey",
            "--key-file",
            str(key_file),
            "--no-strict",
        ],
    )

    assert main() == 0
    assert key_file.exists()
    assert key_file.read_text() == "savedkey"


def test_main_default_output(
    native_distribution: Distribution, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test that main uses a default output path when -o is not specified."""
    code = tmp_path / "run.py"
    code.write_text("pass")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "sys.argv",
        [
            "pystandalone",
            "-c",
            str(code),
            "-d",
            str(native_distribution.path),
            "--no-crypt",
            "--no-strict",
        ],
    )

    assert main() == 0

    # Default output name includes version, target and arch
    outputs = list(tmp_path.glob("pystandalone-*"))
    assert len(outputs) == 1
    assert outputs[0].stat().st_size > 0


def test_main_invalid_code_dir(
    native_distribution: Distribution, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test that main returns 1 for an empty directory with no run.py."""
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()

    monkeypatch.setattr(
        "sys.argv",
        [
            "pystandalone",
            "-c",
            str(empty_dir),
            "-d",
            str(native_distribution.path),
            "--no-strict",
        ],
    )

    assert main() == 1


def test_main_list_available(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture) -> None:
    """Test that --list-available lists distributions and exits successfully."""
    monkeypatch.setattr("sys.argv", ["pystandalone", "--list-available"])

    assert main() == 0

    captured = capsys.readouterr()
    assert "Python" in captured.out
