from __future__ import annotations

import sys
import zipfile
from typing import TYPE_CHECKING

import pytest

from pystandalone.source import Source

if TYPE_CHECKING:
    from pathlib import Path


MOCK_SPEC = """
[run]
entry = myapp:main

[run:other]
entry = other:main

[library]
uu

[modules]
dissect
special

[include]
foo.*

[exclude]
bar.*

[build:special]
special/file.py = some-tool-to-run
"""


def test_source_from_file(tmp_path: Path) -> None:
    """Test that we can create a Source object from a file path."""
    src_file = tmp_path / "script.py"
    src_file.touch()

    source = Source.from_path(src_file)
    assert source.run == str(src_file)
    assert source.base == tmp_path
    assert not source.include_base


def test_source_from_zip(tmp_path: Path) -> None:
    """Test that we can create a Source object from a zip file path."""
    src_zip = tmp_path / "archive.zip"
    src_zip.touch()

    source = Source.from_path(src_zip)
    assert source.run == str(src_zip)
    assert source.base == tmp_path
    assert not source.include_base


def test_source_from_dir_with_run(tmp_path: Path) -> None:
    """Test that we can create a Source object from a directory containing a run.py file."""
    src_file = tmp_path / "run.py"
    src_file.touch()

    source = Source.from_path(tmp_path)
    assert source.run == "run.py"
    assert source.base == tmp_path
    assert source.include_base


def test_source_from_dir_with_spec(tmp_path: Path) -> None:
    """Test that we can create a Source object from a directory containing a .pystandalone spec file."""
    spec_file = tmp_path / ".pystandalone"
    spec_file.write_text(MOCK_SPEC)

    source = Source.from_path(tmp_path)
    assert source.run == "myapp:main"
    assert source.base == tmp_path
    assert not source.include_base
    assert source.library == {"uu"}
    assert source.modules == {"dissect", "myapp", "special"}
    assert source.include == {"foo.*"}
    assert source.exclude == {"bar.*"}


def test_source_from_spec_with_entry(tmp_path: Path) -> None:
    """Test that we can create a Source object from a .pystandalone spec file with an entry selection."""
    spec_file = tmp_path / ".pystandalone"
    spec_file.write_text(MOCK_SPEC)

    source = Source.from_path(tmp_path / ".pystandalone:other")
    assert source.run == "other:main"
    assert source.base == tmp_path
    assert not source.include_base


def test_pack_run_file(tmp_path: Path) -> None:
    """Test that packing a source with a run file yields the run file contents."""
    run_file = tmp_path / "script.py"
    run_file.write_text("print('hello')")

    source = Source.from_path(run_file)
    packed = dict(source.pack())

    assert packed["run.py"] == "print('hello')"


def test_pack_entrypoint_generates_run(tmp_path: Path) -> None:
    """Test that an entrypoint string generates a synthetic run.py."""
    spec_file = tmp_path / ".pystandalone"
    spec_file.write_text("[run]\nentry = myapp:main\n")

    source = Source.from_path(spec_file)
    # Don't try to pack modules, just test run.py generation
    source.modules.clear()
    packed = dict(source.pack())

    assert "import sys" in packed["run.py"]
    assert "from myapp import main" in packed["run.py"]
    assert "sys.exit(main())" in packed["run.py"]


def test_pack_base_includes_all_files(tmp_path: Path) -> None:
    """Test that packing a directory with include_base yields all files except run.py."""
    run_file = tmp_path / "run.py"
    run_file.write_text("pass")
    (tmp_path / "lib.py").write_text("x = 1")
    sub = tmp_path / "pkg"
    sub.mkdir()
    (sub / "mod.py").write_text("y = 2")

    source = Source.from_path(tmp_path)
    packed = dict(source.pack())

    assert "run.py" in packed
    assert packed["lib.py"] == b"x = 1"
    assert packed["pkg/mod.py"] == b"y = 2"


def test_pack_insert_str(tmp_path: Path) -> None:
    """Test that inserted strings are included in the packed output."""
    run_file = tmp_path / "script.py"
    run_file.write_text("pass")

    source = Source.from_path(run_file)
    source.insert_str("extra/config.py", "CFG = True")
    packed = dict(source.pack())

    assert packed["extra/config.py"] == "CFG = True"


def test_pack_insert_file(tmp_path: Path) -> None:
    """Test that inserted files are included in the packed output."""
    run_file = tmp_path / "script.py"
    run_file.write_text("pass")
    data_file = tmp_path / "data.txt"
    data_file.write_text("some data")

    source = Source.from_path(run_file)
    source.insert_file("injected/data.txt", data_file)
    packed = dict(source.pack())

    assert packed["injected/data.txt"] == "some data"


def test_pack_exclude_filter(tmp_path: Path) -> None:
    """Test that exclude patterns filter out matching files during pack."""
    run_file = tmp_path / "run.py"
    run_file.write_text("pass")
    (tmp_path / "keep.py").write_text("keep")
    (tmp_path / "skip.txt").write_text("skip")

    source = Source.from_path(tmp_path)
    source.exclude.add("*.txt")
    packed = dict(source.pack())

    assert "keep.py" in packed
    assert "skip.txt" not in packed


def test_pack_include_overrides_exclude(tmp_path: Path) -> None:
    """Test that include patterns override exclude patterns during pack."""
    run_file = tmp_path / "run.py"
    run_file.write_text("pass")
    (tmp_path / "important.log").write_text("important")
    (tmp_path / "debug.log").write_text("debug")

    source = Source.from_path(tmp_path)
    source.exclude.add("*.log")
    source.include.add("important.log")
    packed = dict(source.pack())

    assert "important.log" in packed
    assert "debug.log" not in packed


def test_pack_namespace_package_generates_init(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that packing a namespace package generates missing __init__.py files."""
    # Create a namespace package (no __init__.py)
    pkg = tmp_path / "nspkg" / "sub"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").touch()
    (pkg / "mod.py").write_text("x = 1")

    spec_file = tmp_path / ".pystandalone"
    spec_file.write_text("[run]\nentry = nspkg.sub:main\n")

    monkeypatch.syspath_prepend(str(tmp_path))
    source = Source.from_path(spec_file)
    packed = dict(source.pack())

    # Top-level module gets a generated __init__.py
    assert packed["nspkg/__init__.py"] == b""
    assert packed["nspkg/sub/__init__.py"] == b""
    assert packed["nspkg/sub/mod.py"] == b"x = 1"


def test_pack_regular_package_generates_init(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that packing a regular package with __init__.py still generates __init__.py entries."""
    pkg = tmp_path / "mypkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("# init")
    (pkg / "core.py").write_text("y = 2")

    spec_file = tmp_path / ".pystandalone"
    spec_file.write_text("[run]\nentry = mypkg:main\n")

    monkeypatch.syspath_prepend(str(tmp_path))
    source = Source.from_path(spec_file)
    packed = dict(source.pack())

    assert "mypkg/__init__.py" in packed
    assert packed["mypkg/core.py"] == b"y = 2"


def test_pack_build_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that build commands are executed and their stdout is packed."""
    pkg = tmp_path / "buildpkg"
    pkg.mkdir()
    (pkg / "__init__.py").touch()

    spec_file = tmp_path / ".pystandalone"
    spec_file.write_text(
        "[run]\nentry = buildpkg:main\n\n"
        "[build:buildpkg]\n"
        f"buildpkg/generated.py = {sys.executable} -c \"import sys; sys.stdout.buffer.write(b'GENERATED = True')\"\n"
    )

    monkeypatch.syspath_prepend(str(tmp_path))
    source = Source.from_path(spec_file)
    packed = dict(source.pack())

    assert packed["buildpkg/generated.py"] == b"GENERATED = True"


def test_pack_build_output_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that a failed build command raises a RuntimeError."""
    pkg = tmp_path / "failpkg"
    pkg.mkdir()
    (pkg / "__init__.py").touch()

    spec_file = tmp_path / ".pystandalone"
    spec_file.write_text(
        "[run]\n"
        "entry = failpkg:main\n\n"
        "[build:failpkg]\n"
        f'failpkg/out.py = {sys.executable} -c "import sys; sys.exit(1)"\n'
    )

    monkeypatch.syspath_prepend(str(tmp_path))
    source = Source.from_path(spec_file)
    with pytest.raises(RuntimeError, match="failed with exit code"):
        dict(source.pack())


def _make_zip(path: Path, files: dict[str, str]) -> None:
    """Helper to create a zip file with the given files."""
    with zipfile.ZipFile(path, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)


def test_pack_zip_run(tmp_path: Path) -> None:
    """Test that packing a zip run file yields all files from the zip."""
    zip_path = tmp_path / "app.zip"
    _make_zip(zip_path, {"run.py": "print('hi')", "lib/util.py": "x = 1"})

    source = Source.from_path(zip_path)
    packed = dict(source.pack())

    assert packed["run.py"] == b"print('hi')"
    assert packed["lib/util.py"] == b"x = 1"


def test_pack_zip_with_insert(tmp_path: Path) -> None:
    """Test that inserts are included on top of zip contents."""
    zip_path = tmp_path / "app.zip"
    _make_zip(zip_path, {"run.py": "pass"})

    source = Source.from_path(zip_path)
    source.insert_str("extra.py", "EXTRA = True")
    packed = dict(source.pack())

    assert packed["run.py"] == b"pass"
    assert packed["extra.py"] == "EXTRA = True"


def test_pack_zip_with_exclude(tmp_path: Path) -> None:
    """Test that exclude patterns filter zip contents."""
    zip_path = tmp_path / "app.zip"
    _make_zip(zip_path, {"run.py": "pass", "tests/test_foo.py": "test", "lib/core.py": "core"})

    source = Source.from_path(zip_path)
    source.exclude.add("tests/*")
    packed = dict(source.pack())

    assert "run.py" in packed
    assert "lib/core.py" in packed
    assert "tests/test_foo.py" not in packed


def test_pack_zip_with_include_overrides_exclude(tmp_path: Path) -> None:
    """Test that include patterns override exclude patterns for zip contents."""
    zip_path = tmp_path / "app.zip"
    _make_zip(zip_path, {"data/keep.dat": "keep", "data/skip.dat": "skip"})

    source = Source.from_path(zip_path)
    source.exclude.add("data/*")
    source.include.add("data/keep.dat")
    packed = dict(source.pack())

    assert "data/keep.dat" in packed
    assert "data/skip.dat" not in packed
