"""Turns the sentence at the top of ruff.toml and mypy.ini into checks that fail the pull request
breaking it.

"Versioned together with lint.py (typecheck.py) and action.yml: a rule change ships in the same
commit as the code; repos pinned to a SHA move deliberately." Main only receives squashed commits
that passed these tests, so no commit that breaks the sentence ever exists on main for a caller
to pin.
"""

from __future__ import annotations

import importlib.metadata
import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
ACTIONS = ROOT / ".github" / "actions" / "python-lint"
RUFF_POLICY = ACTIONS / "run-ruff" / "ruff.toml"
RUFF_REQUIREMENTS = ACTIONS / "run-ruff" / "requirements.txt"
MYPY_POLICY = ACTIONS / "run-mypy" / "mypy.ini"
MYPY_REQUIREMENTS = ACTIONS / "run-mypy" / "requirements.txt"
FIXTURES = ROOT / "tests" / "policy"

FULL_SHA = re.compile(r"[0-9a-f]{40}")


def _content_lines(path: Path) -> list[str]:
    """Lines without comments and blanks."""
    lines = (raw.split("#", 1)[0].strip() for raw in path.read_text().splitlines())
    return [line for line in lines if line]


def _pinned(requirements: Path, package: str) -> str:
    """The exact version of `package` in a requirements file the action installs from."""
    found = [
        line
        for line in _content_lines(requirements)
        if re.split(r"[\s<>=!~;\[@]", line, maxsplit=1)[0].lower() == package
    ]
    where = requirements.relative_to(ROOT)
    assert len(found) == 1, f"{where}: expected one {package} requirement, found {found}"
    match = re.fullmatch(rf"{package}==(\d+\.\d+\.\d+)", found[0].replace(" ", ""))
    assert match, f"{where}: pin {package} exactly ({package}==X.Y.Z), found {found[0]!r}"
    return match.group(1)


def _order(finding: str) -> tuple[int, str]:
    line, _, code = finding.partition(":")
    return int(line), code


def _assert_matches_expected(actual: list[str], expected_file: Path) -> None:
    expected = sorted(_content_lines(expected_file), key=_order)
    assert actual == expected, (
        "The policy's findings changed. If that is the intended rule change, update "
        f"{expected_file.relative_to(ROOT)} in this same commit.\n"
        f"  now reported:       {sorted(set(actual) - set(expected), key=_order)}\n"
        f"  no longer reported: {sorted(set(expected) - set(actual), key=_order)}"
    )


# --- ruff ----------------------------------------------------------------------------------


def test_ruff_pin_and_required_version_agree() -> None:
    """A ruff upgrade changes findings like a rule change, so it must edit ruff.toml too."""
    pinned = _pinned(RUFF_REQUIREMENTS, "ruff")
    required = tomllib.loads(RUFF_POLICY.read_text()).get("required-version")
    assert required == f"=={pinned}", (
        f"ruff.toml has required-version={required!r} but requirements.txt pins "
        f'ruff=={pinned}: set required-version = "=={pinned}" in the same commit'
    )


def _ruff_label(diagnostic: dict[str, Any]) -> str:
    return f"{diagnostic['location']['row']}:{diagnostic['code'] or 'syntax-error'}"


def test_ruff_findings_match_expected(tmp_path: Path) -> None:
    """What the lint policy reports changes only together with ruff/expected.txt."""
    stdin_json = ("--no-cache", "--output-format", "json", "--stdin-filename", "violations.py", "-")
    result = subprocess.run(
        [sys.executable, "-m", "ruff", "check", "--config", str(RUFF_POLICY), *stdin_json],
        input=(FIXTURES / "ruff" / "violations.py.txt").read_text(),
        capture_output=True,
        text=True,
        cwd=tmp_path,  # --config resolves relative excludes from here: keep it neutral
        check=False,
    )
    assert result.returncode in (0, 1), f"ruff failed (exit {result.returncode}):\n{result.stderr}"
    actual = sorted(map(_ruff_label, json.loads(result.stdout)), key=_order)
    _assert_matches_expected(actual, FIXTURES / "ruff" / "expected.txt")


# --- mypy ----------------------------------------------------------------------------------


def test_mypy_pin_is_the_mypy_that_runs() -> None:
    """mypy has no required-version setting, so this is that guard: the findings below always
    come from the pinned mypy, and a stale or conflicting install fails here, by name."""
    pinned = _pinned(MYPY_REQUIREMENTS, "mypy")
    try:
        installed = importlib.metadata.version("mypy")
    except importlib.metadata.PackageNotFoundError:
        installed = "not installed"
    assert installed == pinned, (
        f"mypy {installed} is installed but run-mypy/requirements.txt pins mypy=={pinned}: "
        "install that file (self-test.yml does) and bump the pin only in a commit that also "
        "updates mypy/expected.txt if the findings change"
    )


def test_mypy_findings_match_expected(tmp_path: Path) -> None:
    """What the type-check policy reports changes only together with mypy/expected.txt."""
    fixture = tmp_path / "type_errors.py"
    fixture.write_text((FIXTURES / "mypy" / "type_errors.py.txt").read_text())
    cmd = [sys.executable, "-m", "mypy", fixture.name, "--config-file", str(MYPY_POLICY)]
    cmd += ["--output", "json", "--no-error-summary", "--cache-dir", str(tmp_path / "cache")]
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=tmp_path, check=False)
    assert result.returncode in (0, 1), (
        f"mypy failed (exit {result.returncode}):\n{result.stdout}{result.stderr}"
    )
    errors = [
        item
        for item in map(json.loads, filter(None, result.stdout.splitlines()))
        if item.get("severity") == "error"
    ]
    actual = sorted((f"{e['line']}:{e['code'] or 'syntax'}" for e in errors), key=_order)
    _assert_matches_expected(actual, FIXTURES / "mypy" / "expected.txt")


# --- every uses: ---------------------------------------------------------------------------


def _uses(node: Any) -> list[str]:
    """Every `uses:` value at any depth: job-level reusable-workflow calls and steps."""
    if isinstance(node, dict):
        found = [v for k, v in node.items() if k == "uses" and isinstance(v, str)]
        return found + [ref for v in node.values() for ref in _uses(v)]
    if isinstance(node, list):
        return [ref for item in node for ref in _uses(item)]
    return []


def _this_repository(name: str) -> bool:
    """True when `owner/repo[/path]` names this repository (GITHUB_REPOSITORY in CI)."""
    owner_repo = "/".join(name.split("/")[:2]).lower()
    full = os.environ.get("GITHUB_REPOSITORY", "").lower()
    if full:
        return owner_repo == full
    return owner_repo.partition("/")[2] == ROOT.name.lower()


def _problem(ref: str) -> str | None:
    """Why a `uses:` value could run code from another commit than the caller pinned, if it can."""
    if ref.startswith("$/"):
        return None  # this repository at the running commit: the caller's SHA
    if ref.startswith("./"):
        return "'./' resolves inside the caller's checkout: use '$/'"
    if ref.startswith("docker://"):
        return None if "@sha256:" in ref else "pin the image by digest (@sha256:...)"
    name, _, version = ref.partition("@")
    if _this_repository(name):
        return "this repository by name pins another commit: use '$/'"
    if not FULL_SHA.fullmatch(version):
        return f"'@{version}' can move: pin the full 40-character commit SHA"
    return None


def test_every_uses_is_this_commit_or_a_full_sha() -> None:
    """A caller's SHA must freeze everything it runs, not only the entry point."""
    github = ROOT / ".github"
    patterns = ("workflows/*.y*ml", "**/action.yml", "**/action.yaml")
    files = sorted({path for pattern in patterns for path in github.glob(pattern)})
    assert files, f"no workflow or action files under {github}"
    problems = [
        f"{path.relative_to(ROOT)}: uses: {ref} -> {why}"
        for path in files
        for ref in _uses(yaml.safe_load(path.read_text()))
        if (why := _problem(ref))
    ]
    assert not problems, "\n".join(problems)
