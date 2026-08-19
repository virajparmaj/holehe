"""Regressions for the crash-level bugs in the original holehe core.

These stay until the legacy module tree is deleted; each one corresponds to a
failure that was reachable from a normal command line.
"""

import types

import pytest

import holehe.core as core


def test_check_update_is_gone():
    """It shelled out to `pip3 install --upgrade holehe` on every single run."""
    assert not hasattr(core, "check_update")


def test_help_does_not_require_the_network():
    """check_update() ran before parse_args(), so `--help` hit pypi.org."""
    import inspect
    src = inspect.getsource(core.maincore)
    assert "parse_args" in src
    assert "check_update" not in src


def test_module_domain_table_is_complete():
    """duolingo and facebook were missing, and the lookup was not guarded --
    a KeyError inside an except handler in a nursery child aborted the scan."""
    import os
    names = set()
    root = os.path.join(os.path.dirname(core.__file__), "modules")
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for f in filenames:
            if f.endswith(".py") and f != "__init__.py":
                names.add(f[:-3])
    assert names <= set(core.MODULE_DOMAINS), names - set(core.MODULE_DOMAINS)


@pytest.mark.asyncio
async def test_launch_module_survives_an_unknown_module_name():
    async def mystery(email, client, out):
        raise RuntimeError("boom")

    out = []
    await core.launch_module(mystery, "a@b.com", None, out)
    assert len(out) == 1
    assert out[0]["error"] is True
    assert out[0]["domain"] == "unknown"
    assert "RuntimeError" in out[0]["others"]["errorMessage"]


@pytest.mark.asyncio
async def test_launch_module_reads_the_name_off_the_function():
    """It used to parse str(module), which broke for anything but a plain function."""
    from functools import partial

    async def twitter(email, client, out, extra=None):
        raise RuntimeError("x")

    out = []
    await core.launch_module(partial(twitter, extra=1), "a@b.com", None, out)
    assert len(out) == 1, "a partial used to raise IndexError inside the handler"


def test_csv_export_survives_mixed_row_shapes(tmp_path, monkeypatch):
    """DictWriter derived fieldnames from data[0], so an error row raised ValueError."""
    monkeypatch.chdir(tmp_path)
    normal = {"name": "a", "domain": "a.com", "method": "register",
              "frequent_rate_limit": False, "rateLimit": False, "exists": True,
              "emailrecovery": None, "phoneNumber": None, "others": None}
    errored = {"name": "b", "domain": "b.com", "method": None,
               "frequent_rate_limit": False, "rateLimit": False, "error": True,
               "exists": False, "emailrecovery": None, "phoneNumber": None,
               "others": {"errorMessage": "KeyError"}}
    with pytest.raises(SystemExit):
        core.export_csv([normal, errored], types.SimpleNamespace(csvoutput=True), "e@x.com")
    written = list(tmp_path.glob("*.csv"))
    assert len(written) == 1
    assert written[0].read_text().count("\n") == 3   # header + 2 rows


def test_csv_export_survives_no_results(tmp_path, monkeypatch):
    """data[0] raised IndexError when every module failed."""
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit):
        core.export_csv([], types.SimpleNamespace(csvoutput=True), "e@x.com")
    written = list(tmp_path.glob("*.csv"))
    assert len(written) == 1
    assert written[0].read_text().strip() == ",".join(core.CSV_FIELDNAMES)


def test_no_module_imports_an_undeclared_dependency():
    """facebook.py imported `requests`, which is not a dependency -- and because
    discovery imports every module eagerly, that broke the CLI for every site."""
    import os
    import re
    root = os.path.join(os.path.dirname(core.__file__), "modules")
    offenders = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for f in filenames:
            if not f.endswith(".py"):
                continue
            text = open(os.path.join(dirpath, f), encoding="utf-8").read()
            if re.search(r"^\s*import requests", text, re.M):
                offenders.append(f)
    assert not offenders


def test_every_module_reports_exactly_once_per_branch():
    """strava's except branch appended without returning, so it reported twice."""
    import ast
    import os
    root = os.path.join(os.path.dirname(core.__file__), "modules")
    offenders = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for f in filenames:
            if not f.endswith(".py") or f == "__init__.py":
                continue
            path = os.path.join(dirpath, f)
            tree = ast.parse(open(path, encoding="utf-8").read())
            for node in ast.walk(tree):
                if not isinstance(node, ast.Try):
                    continue
                for handler in node.handlers:
                    appends = any(isinstance(n, ast.Call)
                                  and getattr(n.func, "attr", "") == "append"
                                  for n in ast.walk(handler))
                    exits = any(isinstance(n, (ast.Return, ast.Raise))
                                for n in ast.walk(handler))
                    # only a problem when statements follow the try block
                    idx = None
                    for parent in ast.walk(tree):
                        for field, value in ast.iter_fields(parent):
                            if isinstance(value, list) and node in value:
                                idx = value.index(node), len(value)
                    if appends and not exits and idx and idx[0] < idx[1] - 1:
                        offenders.append(f"{f}:{handler.lineno}")
    assert "strava.py:24" not in offenders
