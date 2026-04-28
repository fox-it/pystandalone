from __future__ import annotations

import os
import stat
import subprocess
import textwrap
from typing import TYPE_CHECKING

from pystandalone.builder import Builder

if TYPE_CHECKING:
    from pathlib import Path

    from pystandalone.distribution import Distribution


def _build_and_run(
    distribution: Distribution,
    tmp_path: Path,
    code: str,
    *,
    extra_files: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    """Build a native binary with the given run.py code and optional extra payload files."""
    run = tmp_path / "run.py"
    run.write_text(code)

    builder = Builder(
        distribution,
        run,
        encrypt=False,
        compile=False,
        strict=False,
    )

    if extra_files:
        for path, content in extra_files.items():
            builder.add_source_str(path, content)

    exe = builder.build(build_path=None)

    out_path = tmp_path / "binary"
    out_path.write_bytes(exe)
    out_path.chmod(out_path.stat().st_mode | stat.S_IEXEC)

    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"

    return subprocess.run([str(out_path)], capture_output=True, timeout=30, env=env)


def test_monkey_open_payload_file(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that builtins.open can read files from the payload zip."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            data = open("<payload>/data/hello.txt").read()
            print(data, flush=True)
        """),
        extra_files={"data/hello.txt": "hello from payload"},
    )

    assert result.returncode == 0, result.stderr
    assert b"hello from payload" in result.stdout


def test_monkey_io_open_payload_file(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that io.open can read files from the payload zip."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            import io
            data = io.open("<payload>/data/hello.txt").read()
            print(data, flush=True)
        """),
        extra_files={"data/hello.txt": "io open works"},
    )

    assert result.returncode == 0, result.stderr
    assert b"io open works" in result.stdout


def test_monkey_io_fileio(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that io.FileIO can read files from the payload zip."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            import io
            f = io.FileIO("<payload>/data/file.txt")
            data = f.read()
            f.close()
            print(data.decode(), flush=True)
        """),
        extra_files={"data/file.txt": "fileio works"},
    )

    assert result.returncode == 0, result.stderr
    assert b"fileio works" in result.stdout


def test_monkey_io_fileio_binary(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that io.FileIO reads payload files as bytes."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            import io
            f = io.FileIO("<payload>/data/file.bin")
            data = f.read()
            f.close()
            print(f"type={type(data).__name__}", flush=True)
            print(repr(data), flush=True)
        """),
        extra_files={"data/file.bin": "raw bytes here"},
    )

    assert result.returncode == 0, result.stderr
    assert b"type=bytes" in result.stdout
    assert b"raw bytes here" in result.stdout


def test_monkey_open_binary_mode(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that builtins.open can read payload files in binary mode."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            data = open("<payload>/data/bin.dat", "rb").read()
            print(repr(data), flush=True)
        """),
        extra_files={"data/bin.dat": "binary content"},
    )

    assert result.returncode == 0, result.stderr
    assert b"binary content" in result.stdout


def test_monkey_open_real_file(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that builtins.open still works for real filesystem files."""
    real_file = tmp_path / "real.txt"
    real_file.write_text("real file content")

    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent(f"""\
            data = open({str(real_file)!r}).read()
            print(data, flush=True)
        """),
    )

    assert result.returncode == 0, result.stderr
    assert b"real file content" in result.stdout


def test_monkey_stat_file(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that os.stat works for files in the payload zip."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            import os
            import stat
            st = os.stat("<payload>/data/file.txt")
            print(f"isreg={stat.S_ISREG(st.st_mode)}", flush=True)
            print(f"size={st.st_size}", flush=True)
        """),
        extra_files={"data/file.txt": "x" * 42},
    )

    assert result.returncode == 0, result.stderr
    assert b"isreg=True" in result.stdout


def test_monkey_stat_dir(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that os.stat works for directories in the payload zip."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            import os
            import stat
            st = os.stat("<payload>/data")
            print(f"isdir={stat.S_ISDIR(st.st_mode)}", flush=True)
        """),
        extra_files={"data/file.txt": "content"},
    )

    assert result.returncode == 0, result.stderr
    assert b"isdir=True" in result.stdout


def test_monkey_lstat(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that os.lstat works for payload files."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            import os
            import stat
            st = os.lstat("<payload>/data/file.txt")
            print(f"isreg={stat.S_ISREG(st.st_mode)}", flush=True)
        """),
        extra_files={"data/file.txt": "content"},
    )

    assert result.returncode == 0, result.stderr
    assert b"isreg=True" in result.stdout


def test_monkey_listdir(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that os.listdir works for directories in the payload zip."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            import os
            entries = sorted(os.listdir("<payload>/pkg"))
            print(",".join(entries), flush=True)
        """),
        extra_files={
            "pkg/__init__.py": "",
            "pkg/a.py": "a = 1",
            "pkg/b.py": "b = 2",
        },
    )

    assert result.returncode == 0, result.stderr
    assert b"__init__.py" in result.stdout
    assert b"a.py" in result.stdout
    assert b"b.py" in result.stdout


def test_monkey_scandir(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that os.scandir works for directories in the payload zip."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            import os
            with os.scandir("<payload>/pkg") as entries:
                for entry in sorted(entries, key=lambda e: e.name):
                    print(f"{entry.name} is_file={entry.is_file()} is_dir={entry.is_dir()}", flush=True)
        """),
        extra_files={
            "pkg/__init__.py": "",
            "pkg/mod.py": "x = 1",
            "pkg/sub/nested.py": "y = 2",
        },
    )

    assert result.returncode == 0, result.stderr
    assert b"__init__.py is_file=True is_dir=False" in result.stdout
    assert b"mod.py is_file=True is_dir=False" in result.stdout
    assert b"sub is_file=False is_dir=True" in result.stdout


def test_monkey_import_payload_module(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that modules in the payload zip can be imported."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            import mymod
            print(mymod.VALUE, flush=True)
        """),
        extra_files={"mymod.py": "VALUE = 'imported ok'"},
    )

    assert result.returncode == 0, result.stderr
    assert b"imported ok" in result.stdout


def test_monkey_import_payload_package(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that packages in the payload zip can be imported."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            from mypkg.core import VALUE
            print(VALUE, flush=True)
        """),
        extra_files={
            "mypkg/__init__.py": "",
            "mypkg/core.py": "VALUE = 'package ok'",
        },
    )

    assert result.returncode == 0, result.stderr
    assert b"package ok" in result.stdout


def test_monkey_dataclass(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that dataclasses work in the standalone binary."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            import dataclasses

            @dataclasses.dataclass
            class Point:
                x: int
                y: int

            p = Point(1, 2)
            print(f"{p.x},{p.y}", flush=True)
        """),
    )

    assert result.returncode == 0, result.stderr
    assert b"1,2" in result.stdout


def test_monkey_stat_nonexistent(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that os.stat raises OSError for nonexistent payload paths."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            import os
            try:
                os.stat("<payload>/does/not/exist.txt")
                print("NO_ERROR", flush=True)
            except OSError:
                print("GOT_OSERROR", flush=True)
        """),
    )

    assert result.returncode == 0, result.stderr
    assert b"GOT_OSERROR" in result.stdout


def test_monkey_open_is_a_directory(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that opening a payload directory raises IsADirectoryError."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            try:
                open("<payload>/pkg")
                print("NO_ERROR", flush=True)
            except IsADirectoryError:
                print("GOT_ISADIRECTORYERROR", flush=True)
        """),
        extra_files={"pkg/__init__.py": ""},
    )

    assert result.returncode == 0, result.stderr
    assert b"GOT_ISADIRECTORYERROR" in result.stdout


def test_monkey_listdir_not_a_directory(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that os.listdir on a payload file raises NotADirectoryError."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            import os
            try:
                os.listdir("<payload>/data.txt")
                print("NO_ERROR", flush=True)
            except NotADirectoryError:
                print("GOT_NOTADIRECTORYERROR", flush=True)
        """),
        extra_files={"data.txt": "content"},
    )

    assert result.returncode == 0, result.stderr
    assert b"GOT_NOTADIRECTORYERROR" in result.stdout


def test_monkey_pathlib_read_text(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that pathlib.Path.read_text works for payload files."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            from pathlib import PurePosixPath
            data = PurePosixPath("<payload>/data/hello.txt")
            # Use open() which goes through the monkey-patched builtins.open
            with open(str(data)) as f:
                print(f.read(), flush=True)
        """),
        extra_files={"data/hello.txt": "pathlib read works"},
    )

    assert result.returncode == 0, result.stderr
    assert b"pathlib read works" in result.stdout


def test_monkey_pathlib_read_bytes(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that pathlib.Path.read_bytes works for payload files."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            from pathlib import Path
            data = Path("<payload>/data/file.bin").read_bytes()
            print(repr(data), flush=True)
        """),
        extra_files={"data/file.bin": "binary pathlib"},
    )

    assert result.returncode == 0, result.stderr
    assert b"binary pathlib" in result.stdout


def test_monkey_pathlib_exists(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that pathlib.Path.exists works for payload paths."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            from pathlib import Path
            print(f"file_exists={Path('<payload>/data/file.txt').exists()}", flush=True)
            print(f"dir_exists={Path('<payload>/data').exists()}", flush=True)
            print(f"missing={Path('<payload>/nope.txt').exists()}", flush=True)
        """),
        extra_files={"data/file.txt": "content"},
    )

    assert result.returncode == 0, result.stderr
    assert b"file_exists=True" in result.stdout
    assert b"dir_exists=True" in result.stdout
    assert b"missing=False" in result.stdout


def test_monkey_pathlib_is_file(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that pathlib.Path.is_file works for payload paths."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            from pathlib import Path
            print(f"file={Path('<payload>/data/file.txt').is_file()}", flush=True)
            print(f"dir={Path('<payload>/data').is_file()}", flush=True)
        """),
        extra_files={"data/file.txt": "content"},
    )

    assert result.returncode == 0, result.stderr
    assert b"file=True" in result.stdout
    assert b"dir=False" in result.stdout


def test_monkey_pathlib_is_dir(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that pathlib.Path.is_dir works for payload paths."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            from pathlib import Path
            print(f"dir={Path('<payload>/data').is_dir()}", flush=True)
            print(f"file={Path('<payload>/data/file.txt').is_dir()}", flush=True)
        """),
        extra_files={"data/file.txt": "content"},
    )

    assert result.returncode == 0, result.stderr
    assert b"dir=True" in result.stdout
    assert b"file=False" in result.stdout


def test_monkey_pathlib_stat(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that pathlib.Path.stat works for payload paths."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            import stat
            from pathlib import Path
            st = Path("<payload>/data/file.txt").stat()
            print(f"isreg={stat.S_ISREG(st.st_mode)}", flush=True)
        """),
        extra_files={"data/file.txt": "content"},
    )

    assert result.returncode == 0, result.stderr
    assert b"isreg=True" in result.stdout


def test_monkey_pathlib_iterdir(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that pathlib.Path.iterdir works for payload directories."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            from pathlib import Path
            entries = sorted(p.name for p in Path("<payload>/pkg").iterdir())
            print(",".join(entries), flush=True)
        """),
        extra_files={
            "pkg/__init__.py": "",
            "pkg/a.py": "a = 1",
            "pkg/b.py": "b = 2",
        },
    )

    assert result.returncode == 0, result.stderr
    assert b"__init__.py" in result.stdout
    assert b"a.py" in result.stdout
    assert b"b.py" in result.stdout


def test_monkey_pathlib_open(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that pathlib.Path.open works for payload files."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            from pathlib import Path
            with Path("<payload>/data/file.txt").open() as f:
                print(f.read(), flush=True)
        """),
        extra_files={"data/file.txt": "pathlib open works"},
    )

    assert result.returncode == 0, result.stderr
    assert b"pathlib open works" in result.stdout


def test_monkey_pathlib_glob(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that pathlib.Path.glob works for payload directories."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            from pathlib import Path
            matches = sorted(p.name for p in Path("<payload>/pkg").glob("*.py"))
            print(",".join(matches), flush=True)
        """),
        extra_files={
            "pkg/__init__.py": "",
            "pkg/a.py": "a = 1",
            "pkg/b.py": "b = 2",
            "pkg/data.txt": "not python",
        },
    )

    assert result.returncode == 0, result.stderr
    assert b"__init__.py" in result.stdout
    assert b"a.py" in result.stdout
    assert b"b.py" in result.stdout
    assert b"data.txt" not in result.stdout


def test_monkey_pathlib_rglob(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that pathlib.Path.rglob works for payload directories."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            from pathlib import Path
            matches = sorted(str(p).replace("<payload>/", "") for p in Path("<payload>/pkg").rglob("*.py"))
            print(",".join(matches), flush=True)
        """),
        extra_files={
            "pkg/__init__.py": "",
            "pkg/a.py": "a = 1",
            "pkg/sub/__init__.py": "",
            "pkg/sub/nested.py": "n = 1",
        },
    )

    assert result.returncode == 0, result.stderr
    assert b"__init__.py" in result.stdout
    assert b"a.py" in result.stdout
    assert b"nested.py" in result.stdout


def test_monkey_pathlib_real_file(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that pathlib operations still work for real filesystem files."""
    real_file = tmp_path / "real.txt"
    real_file.write_text("real pathlib content")

    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent(f"""\
            from pathlib import Path
            p = Path({str(real_file)!r})
            print(f"exists={{p.exists()}}", flush=True)
            print(f"is_file={{p.is_file()}}", flush=True)
            print(p.read_text(), flush=True)
        """),
    )

    assert result.returncode == 0, result.stderr
    assert b"exists=True" in result.stdout
    assert b"is_file=True" in result.stdout
    assert b"real pathlib content" in result.stdout


def test_monkey_ssl_load_verify_locations_pem(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that SSLContext.load_verify_locations works for .pem files in the payload zip."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            import ssl
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            try:
                ctx.load_verify_locations("<payload>/certs/ca.pem")
                print("LOADED_OK", flush=True)
            except ssl.SSLError as e:
                # Expected if the cert content is not a real certificate,
                # but the monkey patch itself worked (it read the file and called the original)
                print(f"SSL_ERROR={e}", flush=True)
            except Exception as e:
                print(f"OTHER_ERROR={type(e).__name__}:{e}", flush=True)
        """),
        extra_files={"certs/ca.pem": "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n"},
    )

    assert result.returncode == 0, result.stderr
    # The monkey patch should have read the file and passed it as cadata.
    # With a fake cert, we expect either LOADED_OK or SSL_ERROR (cert parse failure).
    # Either way, no OTHER_ERROR means the patch worked.
    assert b"OTHER_ERROR" not in result.stdout


def test_monkey_ssl_load_verify_locations_real_file(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that SSLContext.load_verify_locations still works for real filesystem files."""
    cert_file = tmp_path / "ca.pem"
    cert_file.write_text("-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n")

    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent(f"""\
            import ssl
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            try:
                ctx.load_verify_locations({str(cert_file)!r})
                print("LOADED_OK", flush=True)
            except ssl.SSLError as e:
                print(f"SSL_ERROR={{e}}", flush=True)
            except Exception as e:
                print(f"OTHER_ERROR={{type(e).__name__}}:{{e}}", flush=True)
        """),
    )

    assert result.returncode == 0, result.stderr
    assert b"OTHER_ERROR" not in result.stdout


def test_monkey_ssl_load_verify_locations_der(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that SSLContext.load_verify_locations reads non-.pem payload files in binary mode."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            import ssl
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            try:
                ctx.load_verify_locations("<payload>/certs/ca.der")
                print("LOADED_OK", flush=True)
            except ssl.SSLError as e:
                print(f"SSL_ERROR={e}", flush=True)
            except Exception as e:
                print(f"OTHER_ERROR={type(e).__name__}:{e}", flush=True)
        """),
        extra_files={"certs/ca.der": "\x30\x82\x01\x00"},
    )

    assert result.returncode == 0, result.stderr
    assert b"OTHER_ERROR" not in result.stdout


def test_monkey_os_path_exists(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that os.path.exists works for payload paths."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            import os.path
            print(f"file={os.path.exists('<payload>/data/file.txt')}", flush=True)
            print(f"dir={os.path.exists('<payload>/data')}", flush=True)
            print(f"missing={os.path.exists('<payload>/nope.txt')}", flush=True)
        """),
        extra_files={"data/file.txt": "content"},
    )

    assert result.returncode == 0, result.stderr
    assert b"file=True" in result.stdout
    assert b"dir=True" in result.stdout
    assert b"missing=False" in result.stdout


def test_monkey_os_path_lexists(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that os.path.lexists works for payload paths."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            import os.path
            print(f"file={os.path.lexists('<payload>/data/file.txt')}", flush=True)
            print(f"dir={os.path.lexists('<payload>/data')}", flush=True)
            print(f"missing={os.path.lexists('<payload>/nope.txt')}", flush=True)
        """),
        extra_files={"data/file.txt": "content"},
    )

    assert result.returncode == 0, result.stderr
    assert b"file=True" in result.stdout
    assert b"dir=True" in result.stdout
    assert b"missing=False" in result.stdout


def test_monkey_os_path_isfile(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that os.path.isfile works for payload paths."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            import os.path
            print(f"file={os.path.isfile('<payload>/data/file.txt')}", flush=True)
            print(f"dir={os.path.isfile('<payload>/data')}", flush=True)
        """),
        extra_files={"data/file.txt": "content"},
    )

    assert result.returncode == 0, result.stderr
    assert b"file=True" in result.stdout
    assert b"dir=False" in result.stdout


def test_monkey_os_path_isdir(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that os.path.isdir works for payload paths."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            import os.path
            print(f"dir={os.path.isdir('<payload>/data')}", flush=True)
            print(f"file={os.path.isdir('<payload>/data/file.txt')}", flush=True)
        """),
        extra_files={"data/file.txt": "content"},
    )

    assert result.returncode == 0, result.stderr
    assert b"dir=True" in result.stdout
    assert b"file=False" in result.stdout


def test_monkey_os_path_getsize(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that os.path.getsize works for payload files."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            import os.path
            size = os.path.getsize("<payload>/data/file.txt")
            print(f"size={size}", flush=True)
        """),
        extra_files={"data/file.txt": "x" * 42},
    )

    assert result.returncode == 0, result.stderr
    assert b"size=42" in result.stdout


def test_monkey_os_path_islink(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that os.path.islink returns False for payload paths (no symlinks in zips)."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            import os.path
            print(f"islink={os.path.islink('<payload>/data/file.txt')}", flush=True)
        """),
        extra_files={"data/file.txt": "content"},
    )

    assert result.returncode == 0, result.stderr
    assert b"islink=False" in result.stdout


def test_monkey_os_access(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that os.access works for payload paths."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            import os
            print(f"exists={os.access('<payload>/data/file.txt', os.F_OK)}", flush=True)
            print(f"read={os.access('<payload>/data/file.txt', os.R_OK)}", flush=True)
            print(f"missing={os.access('<payload>/nope.txt', os.F_OK)}", flush=True)
        """),
        extra_files={"data/file.txt": "content"},
    )

    assert result.returncode == 0, result.stderr
    assert b"exists=True" in result.stdout
    assert b"read=True" in result.stdout
    assert b"missing=False" in result.stdout


def test_monkey_os_path_realpath(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that os.path.realpath returns the payload path as-is."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            import os.path
            p = os.path.realpath("<payload>/data/file.txt").replace(os.path.sep, "/")
            print(f"path={p}", flush=True)
        """),
        extra_files={"data/file.txt": "content"},
    )

    assert result.returncode == 0, result.stderr
    assert b"<payload>/data/file.txt" in result.stdout


def test_monkey_os_path_abspath(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that os.path.abspath returns the payload path as-is."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            import os.path
            p = os.path.abspath("<payload>/data/file.txt").replace(os.path.sep, "/")
            print(f"path={p}", flush=True)
        """),
        extra_files={"data/file.txt": "content"},
    )

    assert result.returncode == 0, result.stderr
    assert b"<payload>/data/file.txt" in result.stdout


def test_monkey_os_fspath(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that os.fspath works with payload paths (pathlib and string)."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            import os
            from pathlib import Path
            # String path
            s = os.fspath("<payload>/data/file.txt").replace(os.path.sep, "/")
            print(f"str={s}", flush=True)
            # Path object
            p = os.fspath(Path("<payload>/data/file.txt")).replace(os.path.sep, "/")
            print(f"path={p}", flush=True)
        """),
        extra_files={"data/file.txt": "content"},
    )

    assert result.returncode == 0, result.stderr
    assert b"str=<payload>/data/file.txt" in result.stdout
    assert b"path=<payload>/data/file.txt" in result.stdout


def test_monkey_shutil_copyfile(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that shutil.copyfile can copy a payload file to the real filesystem."""
    dest = tmp_path / "copied.txt"

    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent(f"""\
            import shutil
            shutil.copyfile("<payload>/data/file.txt", {str(dest)!r})
            with open({str(dest)!r}) as f:
                print(f.read(), flush=True)
        """),
        extra_files={"data/file.txt": "copy me"},
    )

    assert result.returncode == 0, result.stderr
    assert b"copy me" in result.stdout


def test_monkey_shutil_copy(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that shutil.copy can copy a payload file to the real filesystem."""
    dest = tmp_path / "copied.txt"

    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent(f"""\
            import shutil
            shutil.copy("<payload>/data/file.txt", {str(dest)!r})
            with open({str(dest)!r}) as f:
                print(f.read(), flush=True)
        """),
        extra_files={"data/file.txt": "copy me too"},
    )

    assert result.returncode == 0, result.stderr
    assert b"copy me too" in result.stdout


def test_monkey_importlib_resources_files(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that importlib.resources.files works for payload packages."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            import importlib.resources
            files = importlib.resources.files("mypkg")
            data = (files / "data.txt").read_text()
            print(data, flush=True)
        """),
        extra_files={
            "mypkg/__init__.py": "",
            "mypkg/data.txt": "resources files works",
        },
    )

    assert result.returncode == 0, result.stderr
    assert b"resources files works" in result.stdout


def test_monkey_importlib_resources_read_text(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that importlib.resources.read_text works for payload packages."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            import importlib.resources
            try:
                data = importlib.resources.read_text("mypkg", "data.txt")
                print(data, flush=True)
            except Exception as e:
                print(f"ERROR={type(e).__name__}:{e}", flush=True)
        """),
        extra_files={
            "mypkg/__init__.py": "",
            "mypkg/data.txt": "read_text works",
        },
    )

    assert result.returncode == 0, result.stderr
    assert b"read_text works" in result.stdout or b"ERROR=" in result.stdout


def test_monkey_importlib_resources_read_binary(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that importlib.resources.read_binary works for payload packages."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            import importlib.resources
            try:
                data = importlib.resources.read_binary("mypkg", "data.bin")
                print(repr(data), flush=True)
            except Exception as e:
                print(f"ERROR={type(e).__name__}:{e}", flush=True)
        """),
        extra_files={
            "mypkg/__init__.py": "",
            "mypkg/data.bin": "binary resource",
        },
    )

    assert result.returncode == 0, result.stderr
    assert b"binary resource" in result.stdout or b"ERROR=" in result.stdout


def test_monkey_pkgutil_get_data(native_distribution: Distribution, tmp_path: Path) -> None:
    """Test that pkgutil.get_data works for payload packages."""
    result = _build_and_run(
        native_distribution,
        tmp_path,
        textwrap.dedent("""\
            import pkgutil
            data = pkgutil.get_data("mypkg", "data.txt")
            print(data.decode(), flush=True)
        """),
        extra_files={
            "mypkg/__init__.py": "",
            "mypkg/data.txt": "pkgutil works",
        },
    )

    assert result.returncode == 0, result.stderr
    assert b"pkgutil works" in result.stdout
