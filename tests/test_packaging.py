"""The catalogue must actually ship.

setup.py had include_package_data=True with no MANIFEST.in and no package_data,
and the repo had zero non-.py files -- so the first YAML added would have worked
from a git checkout and been silently missing from the wheel.
"""

import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def test_package_data_is_declared():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "[tool.setuptools.package-data]" in text
    assert "catalogue/**/*.yaml" in text


def test_manifest_covers_the_sdist():
    text = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
    assert "recursive-include offlist/catalogue" in text


def test_dockerfile_does_not_use_removed_setup_py_install():
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "setup.py install" not in text
    assert "pip install" in text


def test_catalogue_is_reachable_through_importlib_resources():
    """Not via __file__ + os.path.join, which breaks in a zipapp."""
    from offlist.catalogue.loader import catalogue_root
    assert (catalogue_root() / "sites").is_dir()


@pytest.mark.slow
def test_built_wheel_contains_the_catalogue(tmp_path):
    """The assertion that stops a silently empty release."""
    try:
        import build  # noqa: F401
    except ImportError:
        pytest.skip("`build` not installed")
    subprocess.run([sys.executable, "-m", "build", "--wheel", "--outdir", str(tmp_path)],
                   cwd=ROOT, check=True, capture_output=True)
    wheels = list(tmp_path.glob("*.whl"))
    assert wheels, "no wheel produced"
    names = zipfile.ZipFile(wheels[0]).namelist()
    yamls = [n for n in names if n.endswith(".yaml")]
    assert any("catalogue/sites/" in n for n in yamls), "site definitions missing from wheel"
    assert any("catalogue/engines/" in n for n in yamls), "engines missing from wheel"
    assert any("data/" in n for n in names), "remediation data missing from wheel"
