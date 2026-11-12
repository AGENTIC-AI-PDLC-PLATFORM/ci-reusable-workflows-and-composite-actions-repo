"""Turns the security-scan policy into checks that fail the pull request breaking it.

What bandit, semgrep and pip-audit report through this repository's scripts is part of the policy,
like the findings of ruff and mypy: it changes only together with tests/policy/<tool>/expected.txt,
in the same commit. The tests run the scripts the actions run (scan.py, rule_scan.py, audit.py),
each under the interpreter that has its scanner: ORG_CI_<TOOL>_PYTHON when set (self-test.yml gives
every scanner the venv its action uses, installed from its own lock), else the interpreter running
pytest.

The pip-audit tests that query PyPI's advisory service run only when ORG_CI_ONLINE=1.
"""

from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent
ACTIONS = ROOT / ".github" / "actions" / "security-scan"
BANDIT = ACTIONS / "run-bandit"
PIP_AUDIT = ACTIONS / "run-pip-audit"
SEMGREP = ACTIONS / "run-semgrep"
FIXTURES = ROOT / "tests" / "policy"

ONLINE = os.environ.get("ORG_CI_ONLINE") == "1"
online = pytest.mark.skipif(not ONLINE, reason="queries PyPI: set ORG_CI_ONLINE=1 to run it")

# What each script prints per finding: `file:line:col: code ...` (pip-audit has no column).
FINDING = re.compile(r"^(?P<file>[^:\s]+):(?P<line>\d+):(?:(?P<col>\d+):)? (?P<code>\S+)")


def _content_lines(path: Path) -> list[str]:
    """Lines without comments and blanks."""
    lines = (raw.split("#", 1)[0].strip() for raw in path.read_text().splitlines())
    return [line for line in lines if line]


def _pinned(action: Path, package: str) -> str:
    """The exact version of `package` in the requirements.in of an action."""
    pins = [line for line in _content_lines(action / "requirements.in") if line.startswith(package)]
    match = re.fullmatch(rf"{re.escape(package)}==(\S+)", pins[0]) if len(pins) == 1 else None
    assert match, f"{action.name}/requirements.in: pin {package} exactly, found {pins}"
    return match.group(1)


def _python(tool: str) -> str:
    """The interpreter that has `tool` installed."""
    return os.environ.get(f"ORG_CI_{tool.upper().replace('-', '_')}_PYTHON") or sys.executable


def _installed(tool: str) -> str:
    code = f"import importlib.metadata as m; print(m.version('{tool}'))"
    result = subprocess.run(
        [_python(tool), "-c", code], capture_output=True, text=True, check=False
    )
    return result.stdout.strip() if result.returncode == 0 else "not installed"


def _run(
    tool: str, script: Path, *args: str, cwd: Path
) -> tuple[subprocess.CompletedProcess[str], dict[str, str]]:
    """Run an action's script as the action does. Returns the process and its step outputs."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GITHUB_")}
    # The step-output file lives outside `cwd`: the scanned folder stays as the test made it.
    with tempfile.TemporaryDirectory(prefix="org-ci-step-") as tmp:
        output_file = Path(tmp) / "output"
        output_file.write_text("")
        env["GITHUB_OUTPUT"] = str(output_file)
        result = subprocess.run(
            [_python(tool), str(script), *args],
            capture_output=True,
            text=True,
            cwd=cwd,
            env=env,
            check=False,
        )
        outputs = {}
        for line in output_file.read_text().splitlines():
            name, separator, value = line.partition("=")
            if separator:
                outputs[name] = value
    return result, outputs


def _findings(result: subprocess.CompletedProcess[str], with_file: bool = False) -> list[str]:
    found = []
    for line in result.stdout.splitlines():
        match = FINDING.match(line)
        if match:
            label = f"{match['line']}:{match['code']}"
            found.append(f"{match['file']}:{label}" if with_file else label)
    return found


def _assert_matches_expected(actual: list[str], expected_file: Path) -> None:
    expected = sorted(_content_lines(expected_file))
    actual = sorted(actual)
    assert actual == expected, (
        "The policy's findings changed. If that is the intended rule change, update "
        f"{expected_file.relative_to(ROOT)} in this same commit.\n"
        f"  now reported:       {sorted(set(actual) - set(expected))}\n"
        f"  no longer reported: {sorted(set(expected) - set(actual))}"
    )


def _load(script: Path) -> Any:
    """An action's script as a module, to test its pure functions without running a scanner."""
    spec = importlib.util.spec_from_file_location(script.stem.replace("-", "_"), script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve their annotations through sys.modules
    spec.loader.exec_module(module)
    return module


# --- bandit --------------------------------------------------------------------------------


def _bandit_fixture(tmp_path: Path) -> Path:
    (tmp_path / "insecure.py").write_text((FIXTURES / "bandit" / "insecure.py.txt").read_text())
    return tmp_path


def test_bandit_pin_is_the_bandit_that_runs() -> None:
    """bandit has no required-version setting, so this is that guard: the findings below always
    come from the pinned bandit."""
    pinned = _pinned(BANDIT, "bandit")
    assert _installed("bandit") == pinned, (
        f"bandit {_installed('bandit')} runs but run-bandit/requirements.in pins bandit=={pinned}: "
        "install run-bandit/requirements.txt, or point ORG_CI_BANDIT_PYTHON at the venv that has it"
    )


def test_bandit_findings_match_expected(tmp_path: Path) -> None:
    """What the code scan reports at the org thresholds changes only with bandit/expected.txt."""
    result, outputs = _run(
        "bandit", BANDIT / "scan.py", "--mode", "report", cwd=_bandit_fixture(tmp_path)
    )
    assert result.returncode == 0, (
        f"scan.py failed (exit {result.returncode}):\n{result.stdout}{result.stderr}"
    )
    actual = _findings(result)
    _assert_matches_expected(actual, FIXTURES / "bandit" / "expected.txt")
    assert outputs.get("issues") == str(len(actual))


def test_bandit_thresholds_are_what_keeps_the_rest_silent(tmp_path: Path) -> None:
    """The fixture's low-severity and low-confidence lines are found, then filtered: lowering
    either threshold is a rule change, and it shows here."""
    fixture = _bandit_fixture(tmp_path)
    at_org_thresholds = set(
        _findings(_run("bandit", BANDIT / "scan.py", "--mode", "report", cwd=fixture)[0])
    )
    low = ("--severity", "low", "--confidence", "low")
    everything = set(
        _findings(_run("bandit", BANDIT / "scan.py", "--mode", "report", *low, cwd=fixture)[0])
    )
    assert at_org_thresholds < everything
    only_below = {finding.split(":")[1] for finding in everything - at_org_thresholds}
    assert {"B105", "B608"} <= only_below, (
        f"expected B105 and B608 below the thresholds: {only_below}"
    )


def test_bandit_enforce_fails_and_report_does_not(tmp_path: Path) -> None:
    fixture = _bandit_fixture(tmp_path)
    assert _run("bandit", BANDIT / "scan.py", "--mode", "enforce", cwd=fixture)[0].returncode == 1
    assert _run("bandit", BANDIT / "scan.py", "--mode", "report", cwd=fixture)[0].returncode == 0
    assert _run("bandit", BANDIT / "scan.py", "--path", "missing", cwd=fixture)[0].returncode == 2


# --- semgrep -------------------------------------------------------------------------------

SEMGREP_FIXTURES = {
    "data_flow.py.txt": "data_flow.py",
    "workflow.yml.txt": ".github/workflows/workflow.yml",
    "Dockerfile.txt": "Dockerfile",
}


def _semgrep_fixture(tmp_path: Path) -> Path:
    """The fixtures under the names they are scanned as (expected.txt uses those names)."""
    for stored, scanned in SEMGREP_FIXTURES.items():
        target = tmp_path / scanned
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text((FIXTURES / "semgrep" / stored).read_text())
    return tmp_path


def _semgrep(cwd: Path, *args: str) -> tuple[subprocess.CompletedProcess[str], dict[str, str]]:
    return _run(
        "semgrep", SEMGREP / "rule_scan.py", "--config", str(SEMGREP / "rules"), *args, cwd=cwd
    )


def _rule_ids() -> set[str]:
    return {
        rule
        for file in sorted((SEMGREP / "rules").glob("*.yml"))
        for rule in re.findall(r"^\s*-\s+id:\s*(\S+)\s*$", file.read_text(), re.MULTILINE)
    }


def test_semgrep_pin_is_the_semgrep_that_runs() -> None:
    """A semgrep upgrade changes findings like a rule change: they always come from the pin."""
    pinned = _pinned(SEMGREP, "semgrep")
    assert _installed("semgrep") == pinned, (
        f"semgrep {_installed('semgrep')} runs but run-semgrep/requirements.in pins "
        f"semgrep=={pinned}: install run-semgrep/requirements.txt, or point ORG_CI_SEMGREP_PYTHON "
        "at the venv that has it"
    )


def test_semgrep_findings_match_expected(tmp_path: Path) -> None:
    """What the org rules report changes only together with semgrep/expected.txt."""
    result, outputs = _semgrep(_semgrep_fixture(tmp_path), "--mode", "report")
    assert result.returncode == 0, (
        f"rule_scan.py failed (exit {result.returncode}):\n{result.stdout}{result.stderr}"
    )
    actual = _findings(result, with_file=True)
    _assert_matches_expected(actual, FIXTURES / "semgrep" / "expected.txt")
    assert outputs.get("issues") == str(len(actual))


def test_every_semgrep_rule_has_a_case_in_the_fixtures() -> None:
    """A rule without an expected finding could stop matching and nobody would know."""
    expected = {
        line.rsplit(":", 1)[1] for line in _content_lines(FIXTURES / "semgrep" / "expected.txt")
    }
    declared = _rule_ids()
    assert declared, "no rule found under run-semgrep/rules"
    assert declared == expected, (
        f"rules without a fixture case: {sorted(declared - expected)}; "
        f"expected findings of unknown rules: {sorted(expected - declared)}"
    )


def test_semgrep_enforce_fails_and_report_does_not(tmp_path: Path) -> None:
    fixture = _semgrep_fixture(tmp_path)
    assert _semgrep(fixture, "--mode", "enforce")[0].returncode == 1
    assert _semgrep(fixture, "--mode", "report")[0].returncode == 0
    assert _semgrep(fixture, "--path", "missing")[0].returncode == 2


def test_semgrep_baseline_reports_only_what_the_change_adds(tmp_path: Path) -> None:
    """On a pull request security-scan.yml passes the base commit: findings already in it do
    not block the pull request, the ones it adds do."""
    repo = _semgrep_fixture(tmp_path)
    identity = ["-c", "user.name=policy-test", "-c", "user.email=policy-test@example.invalid"]

    def git(*args: str) -> str:
        cmd = ["git", *identity, *args]
        return subprocess.run(
            cmd, cwd=repo, capture_output=True, text=True, check=True
        ).stdout.strip()

    git("init", "--quiet")
    git("add", "--all")
    git("commit", "--quiet", "--message", "base: the fixtures, with all their findings")
    base = git("rev-parse", "HEAD")
    (repo / "added.py").write_text("import os\n\n\ndef added() -> None:\n    os.system(input())\n")
    git("add", "--all")
    git("commit", "--quiet", "--message", "change: one more finding")

    everything = _findings(_semgrep(repo, "--mode", "report")[0], with_file=True)
    result, outputs = _semgrep(repo, "--mode", "enforce", "--baseline-commit=HEAD^1")
    added = _findings(result, with_file=True)
    assert added == ["added.py:5:org.python.tainted-command-execution"], (
        result.stdout + result.stderr
    )
    assert result.returncode == 1 and outputs.get("issues") == "1"
    assert len(everything) == len(_content_lines(FIXTURES / "semgrep" / "expected.txt")) + 1
    # The scan leaves the checkout as it found it: same commit, nothing modified.
    assert git("rev-parse", "HEAD") != base and git("status", "--porcelain") == ""
    # A baseline that is not in the checkout is an error, never a silent full scan.
    unknown = _semgrep(repo, "--baseline-commit=0000000000000000000000000000000000000000")[0]
    assert unknown.returncode == 2 and "baseline commit" in unknown.stdout


# --- pip-audit -----------------------------------------------------------------------------

HASH = "--hash=sha256:" + "0" * 64
# The lock files of uv, Poetry, PDM and Pipenv for one project, as those tools wrote them
# (tests/policy/pip-audit/locked.txt says what the project is): stored name -> real name.
LOCK_FIXTURES = {
    "uv.lock.txt": "uv.lock",
    "poetry.lock.txt": "poetry.lock",
    "pdm.lock.txt": "pdm.lock",
    "Pipfile.lock.txt": "Pipfile.lock",
}


def _stage_lock(stored: str, project: Path) -> Path:
    """A lock fixture under its real name, in a project folder that holds nothing else."""
    project.mkdir(parents=True)
    lock = project / LOCK_FIXTURES[stored]
    lock.write_text((FIXTURES / "pip-audit" / stored).read_text())
    return lock


def _refused(error: type[Exception], call: Callable[..., object], *args: object) -> str:
    """What `call(*args)` is refused with: the text of the `error` it raises, or "" when it is
    not refused."""
    try:
        call(*args)
    except error as refusal:
        return str(refusal) or error.__name__
    return ""


def test_pip_audit_pin_is_the_pip_audit_that_runs() -> None:
    pinned = _pinned(PIP_AUDIT, "pip-audit")
    assert _installed("pip-audit") == pinned, (
        f"pip-audit {_installed('pip-audit')} runs but run-pip-audit/requirements.in pins "
        f"pip-audit=={pinned}: install run-pip-audit/requirements.txt, or point "
        "ORG_CI_PIP_AUDIT_PYTHON at the venv that has it"
    )


def test_pip_audit_finds_what_to_audit_by_itself(tmp_path: Path) -> None:
    """No requirements input is needed: pylock.toml, else the lock file of uv, Poetry, PDM or
    Pipenv, else requirements*.txt, else pyproject.toml. Exact versions come first."""
    audit = _load(PIP_AUDIT / "audit.py")
    project, work = tmp_path / "project", tmp_path / "work"
    project.mkdir()
    work.mkdir()

    nothing = audit.make_plan(project, [], work)
    assert nothing.runs == [] and nothing.label == ""

    (project / "pyproject.toml").write_text(
        '[project]\nname = "demo"\ndependencies = ["requests"]\n'
    )
    plan = audit.make_plan(project, [], work)
    assert plan.runs == [[str(project)]] and plan.label.endswith("pyproject.toml")

    (project / "requirements.txt").write_text("requests>=2\n")
    (project / "requirements-dev.txt").write_text("pytest\n")
    plan = audit.make_plan(project, [], work)
    files = [str(project / "requirements-dev.txt"), str(project / "requirements.txt")]
    assert plan.runs == [["-r", files[0], "-r", files[1]]]

    (project / "uv.lock").write_text((FIXTURES / "pip-audit" / "uv.lock.txt").read_text())
    plan = audit.make_plan(project, [], work)
    assert plan.label.endswith("uv.lock"), "a lock file states exact versions: it comes first"
    assert [run[:3] for run in plan.runs] == [["--no-deps", "--disable-pip", "-r"]]

    (project / "pylock.toml").write_text('lock-version = "1.0"\n[[packages]]\nname = "requests"\n')
    plan = audit.make_plan(project, [], work)
    assert plan.runs == [["--locked", str(project)]] and plan.label.endswith("pylock.toml")
    assert plan.warnings == []


def test_pip_audit_requirements_input_replaces_the_search(tmp_path: Path) -> None:
    audit = _load(PIP_AUDIT / "audit.py")
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "demo"\n')
    chosen = tmp_path / "pins.txt"
    chosen.write_text("requests==2.0\n")
    plan = audit.make_plan(tmp_path, [str(chosen)], tmp_path)
    assert plan.runs == [["-r", str(chosen)]]
    with pytest.raises(audit.AuditError):
        audit.make_plan(tmp_path, [str(tmp_path / "missing.txt")], tmp_path)

    # A lock file given by name is read as the lock it is, next to the requirement files.
    lock = _stage_lock("poetry.lock.txt", tmp_path / "service")
    plan = audit.make_plan(tmp_path, [str(lock), str(chosen)], tmp_path)
    assert len(plan.runs) == 2
    assert plan.runs[0][:3] == ["--no-deps", "--disable-pip", "-r"]
    assert plan.runs[1] == ["-r", str(chosen)]


def test_pip_audit_reads_the_lock_files_of_uv_poetry_pdm_and_pipenv(tmp_path: Path) -> None:
    """pip-audit cannot read these formats, so audit.py does. The four fixtures are the tools'
    own lock files for one project: each must give the same pins, whatever the marker or the
    group of a package, list what is locked from git or a URL as not audited, and leave the
    project's own code out of both."""
    audit = _load(PIP_AUDIT / "audit.py")
    expected = _content_lines(FIXTURES / "pip-audit" / "locked.txt")
    pins = sorted(line for line in expected if "==" in line)
    elsewhere = sorted(line for line in expected if "==" not in line)
    assert pins and elsewhere
    for stored, name in LOCK_FIXTURES.items():
        work = tmp_path / stored / "work"
        lock = _stage_lock(stored, tmp_path / stored / "project")
        work.mkdir()
        plan = audit.make_plan(lock.parent, [], work)
        assert plan.label.endswith(name) and plan.warnings == [], (name, plan.warnings)
        assert [run[:3] for run in plan.runs] == [["--no-deps", "--disable-pip", "-r"]], name
        assert sorted(Path(plan.runs[0][3]).read_text().split()) == pins, name
        assert sorted(item.split(" (")[0] for item in plan.elsewhere) == elsewhere, name
        # A finding is annotated on the line where the lock file starts the package's entry.
        line = plan.locations["urllib3"][1]
        assert "urllib3" in lock.read_text().splitlines()[line - 1], (name, line)

    # A lock made for several platforms can hold two versions of one package: both are
    # audited, in two runs (pip-audit refuses them in one).
    forked = tmp_path / "forked" / "uv.lock"
    forked.parent.mkdir()
    entry = '[[package]]\nname = "numpy"\nversion = "{}"\nsource = {{ registry = "https://x" }}\n'
    forked.write_text("version = 1\n" + entry.format("1.26.4") + entry.format("2.1.0"))
    plan = audit.make_plan(forked.parent, [], tmp_path)
    assert [Path(run[3]).read_text().split() for run in plan.runs] == [
        ["numpy==1.26.4"],
        ["numpy==2.1.0"],
    ]


def test_pip_audit_says_when_it_cannot_read_a_lock_file(tmp_path: Path) -> None:
    """A lock file in a shape audit.py does not know is never read by guessing. The next
    source is audited and a warning says so; with nothing else to audit, or when the file was
    asked for by name, the audit fails instead of reporting nothing."""
    audit = _load(PIP_AUDIT / "audit.py")
    lock = tmp_path / "uv.lock"
    lock.write_text("version = 2\n")
    alone = _refused(audit.AuditError, audit.make_plan, tmp_path, [], tmp_path)
    assert "no other dependency file" in alone, (
        "a lock that cannot be read, and nothing else to audit: the audit must fail, not pass "
        f"as a project without dependencies (refused with: {alone!r})"
    )
    by_name = _refused(audit.AuditError, audit.make_plan, tmp_path, [str(lock)], tmp_path)
    assert "not readable" in by_name, (
        "a lock asked for by name that cannot be read: the audit must fail "
        f"(refused with: {by_name!r})"
    )

    (tmp_path / "pyproject.toml").write_text('[project]\nname = "demo"\n')
    plan = audit.make_plan(tmp_path, [], tmp_path)
    assert plan.runs == [[str(tmp_path)]] and plan.label.endswith("pyproject.toml")
    assert len(plan.warnings) == 1, plan.warnings
    assert "uv.lock (lock format version 2" in plan.warnings[0]
    assert "pyproject.toml was audited instead" in plan.warnings[0]

    # A project without dependencies is not an unreadable lock: nothing to say.
    lock.write_text('version = 1\n[[package]]\nname = "demo"\nsource = { virtual = "." }\n')
    plan = audit.make_plan(tmp_path, [], tmp_path)
    assert plan.label.endswith("pyproject.toml") and plan.warnings == []

    # Not the format its name says, or a name or version that is not one (the values end up
    # in a requirements file written for pip-audit): refused, with the reason.
    registry = 'source = { registry = "https://pypi.org/simple" }'
    unreadable = {
        "uv.lock": f'version = 1\n[[package]]\nname = "a"\nversion = "1 --pre"\n{registry}\n',
        "poetry.lock": '[[package]]\nname = "a"\nversion = "1.0"\n',
        "pdm.lock": '[metadata]\nlock_version = "4.5.1"\n[[package]]\nname = "-r x"\n',
        "Pipfile.lock": '{"_meta": {}, "default": {"a": {"version": ">=1.0"}}}',
    }
    for name, text in unreadable.items():
        (tmp_path / name).write_text(text)
        assert _refused(audit.UnreadableLock, audit.read_lock, tmp_path / name), (
            f"{name} was read as a lock although it holds {text!r}"
        )
    for name in LOCK_FIXTURES.values():
        (tmp_path / name).write_text("{ this is neither TOML nor JSON")
        assert _refused(audit.UnreadableLock, audit.read_lock, tmp_path / name), (
            f"{name} was read as a lock although it is neither TOML nor JSON"
        )


def test_pip_audit_audits_every_pin_of_a_complete_lock(tmp_path: Path) -> None:
    """A hash-locked file is audited as written: pins behind environment markers included,
    two versions of one package in two runs, and without installing anything."""
    audit = _load(PIP_AUDIT / "audit.py")
    lock = tmp_path / "requirements.txt"
    lock.write_text(
        "# generated\n"
        f"alpha==1.0 \\\n    {HASH}\n    # via beta\n"
        f"beta==2.0 ; sys_platform == 'win32' \\\n    {HASH} \\\n    {HASH}\n"
        f"gamma==3.0 ; python_full_version < '3.11' \\\n    {HASH}\n"
        f"gamma==4.0 ; python_full_version >= '3.11' \\\n    {HASH}\n"
    )
    work = tmp_path / "work"
    work.mkdir()
    plan = audit.make_plan(tmp_path, [str(lock)], work)
    assert [run[:3] for run in plan.runs] == [["--require-hashes", "--disable-pip", "-r"]] * 2
    audited = [Path(run[3]).read_text().split() for run in plan.runs]
    assert [[word for word in run if "==" in word] for run in audited] == [
        ["alpha==1.0", "beta==2.0", "gamma==3.0"],
        ["gamma==4.0"],
    ]
    assert plan.locations["beta"] == (plan.fallback_file, 5)

    # One unhashed line, or an included file, and it is no longer a complete lock: pip-audit
    # resolves it instead.
    lock.write_text(f"alpha==1.0 {HASH}\nbeta==2.0\n")
    assert audit.make_plan(tmp_path, [str(lock)], work).runs == [["-r", str(lock)]]
    lock.write_text(f"-r other.txt\nalpha==1.0 {HASH}\n")
    assert audit.make_plan(tmp_path, [str(lock)], work).runs == [["-r", str(lock)]]


def test_pip_audit_enforce_fails_when_it_cannot_audit(tmp_path: Path) -> None:
    """No report is not "no vulnerabilities": enforce fails, report only warns."""
    args = ("--requirements", "missing.txt")
    enforce, _ = _run("pip-audit", PIP_AUDIT / "audit.py", *args, "--mode", "enforce", cwd=tmp_path)
    report, _ = _run("pip-audit", PIP_AUDIT / "audit.py", *args, "--mode", "report", cwd=tmp_path)
    assert enforce.returncode == 2 and "::error" in enforce.stdout
    assert report.returncode == 0 and "::warning" in report.stdout


@online
def test_pip_audit_reports_and_accepts_known_vulnerabilities(tmp_path: Path) -> None:
    """The fixture's pin has known vulnerabilities: found without being told where to look,
    failing in enforce mode, and no longer reported once they are accepted with --ignore-vuln."""
    fixture = (FIXTURES / "pip-audit" / "vulnerable-pins.txt").read_text()
    (tmp_path / "requirements.txt").write_text(fixture)
    expected = set(_content_lines(FIXTURES / "pip-audit" / "expected.txt"))

    result, outputs = _run("pip-audit", PIP_AUDIT / "audit.py", "--mode", "enforce", cwd=tmp_path)
    first_report = result.stdout
    reported = set(outputs.get("vulnerabilities", "").split())
    assert result.returncode == 1, result.stdout + result.stderr
    assert outputs.get("audited") == "requirements.txt"
    assert expected <= reported, f"no longer reported: {sorted(expected - reported)}"
    assert outputs.get("issues") == str(len(reported))

    in_report_mode, _ = _run("pip-audit", PIP_AUDIT / "audit.py", "--mode", "report", cwd=tmp_path)
    assert in_report_mode.returncode == 0

    accepted = f"--ignore-vuln={' '.join(sorted(reported))}"
    result, outputs = _run(
        "pip-audit", PIP_AUDIT / "audit.py", "--mode", "enforce", accepted, cwd=tmp_path
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert outputs.get("issues") == "0" and outputs.get("vulnerabilities") == ""

    # Accepting one advisory by an alias (its CVE or GHSA id) removes exactly that one.
    one = sorted(expected)[0]
    aliases = re.search(rf"{re.escape(one)} \(([^)]+)\)", first_report)
    assert aliases, f"{one} is reported without an alias:\n{first_report}"
    by_alias = f"--ignore-vuln={aliases.group(1).split(', ')[0]}"
    result, outputs = _run("pip-audit", PIP_AUDIT / "audit.py", by_alias, cwd=tmp_path)
    assert set(outputs.get("vulnerabilities", "").split()) == reported - {one}


@online
def test_pip_audit_audits_the_versions_a_lock_file_holds(tmp_path: Path) -> None:
    """Each lock fixture holds the old pin of vulnerable-pins.txt: found without being told
    where to look, in the lock file of each tool, with the same advisories."""
    expected = set(_content_lines(FIXTURES / "pip-audit" / "expected.txt"))
    for stored, name in LOCK_FIXTURES.items():
        project = _stage_lock(stored, tmp_path / stored).parent
        result, outputs = _run(
            "pip-audit", PIP_AUDIT / "audit.py", "--mode", "enforce", cwd=project
        )
        reported = set(outputs.get("vulnerabilities", "").split())
        assert result.returncode == 1, result.stdout + result.stderr
        assert outputs.get("audited") == name
        assert expected <= reported, f"{name}: no longer reported: {sorted(expected - reported)}"
        assert f"{name}:" in result.stdout and "urllib3 1.24.1" in result.stdout
        assert "not audited: sampleproject (git)" in result.stdout, result.stdout
