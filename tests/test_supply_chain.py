"""Turns the supply-chain statements of ENFORCEMENT.md into checks that fail the pull request
breaking them.

The tools this repository installs are dependencies of every repository that calls it. So: each
one is pinned in a requirements.in and installed from the complete, hash-locked requirements.txt
generated beside it, with pip --require-hashes; every lock is audited, signature-checked and
watched by Dependabot; no step downloads an executable; each scanner has its own mode; the
workflows of enforced mode run the org policies as shipped; self-test leaves its checkout as it
found it; and the pre-commit hooks are the tools CI runs.

Everything here reads files only, except the last test, which asks the hook repositories for
their tags and runs only when ORG_CI_ONLINE=1.
"""

from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
GITHUB = ROOT / ".github"
ACTIONS = GITHUB / "actions"
WORKFLOWS = GITHUB / "workflows"
SCAN = WORKFLOWS / "security-scan.yml"
SELF_TEST = WORKFLOWS / "self-test.yml"
RUFF_POLICY = ACTIONS / "python-lint" / "run-ruff" / "ruff.toml"
PUBLISHERS = ACTIONS / "supply-chain" / "verify-signatures" / "publishers.toml"
PRE_COMMIT = {
    "this repository": ROOT / ".pre-commit-config.yaml",
    "the consumer example": ROOT / "examples" / "consumer-repo-example" / ".pre-commit-config.yaml",
}
INSTALL_DEPENDENCIES = "$/.github/actions/common/install-dependencies"

FULL_SHA = re.compile(r"[0-9a-f]{40}")
PIN = re.compile(r"(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?P<version>\d+(?:\.\d+)+)")
FROZEN_REV = re.compile(r"^\s*rev:\s*(?P<rev>\S+)\s+#\s*frozen:\s*(?P<tag>\S+)\s*$", re.MULTILINE)
COMPILE = "uv pip compile requirements.in --universal --generate-hashes --python-version"
ONLINE = os.environ.get("ORG_CI_ONLINE") == "1"


def _rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def _load(script: Path) -> Any:
    """An action's script as a module, to reuse its parser instead of copying it."""
    spec = importlib.util.spec_from_file_location(script.stem.replace("-", "_"), script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve their annotations through sys.modules
    spec.loader.exec_module(module)
    return module


def _normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _pin_files() -> list[Path]:
    """Every requirements.in: one per tool, next to the action (or the tests) that uses it."""
    found = sorted([*ACTIONS.rglob("requirements.in"), ROOT / "tests" / "requirements.in"])
    assert len(found) >= 7, f"expected the requirements.in of every tool, found {found}"
    return found


def _locks() -> list[str]:
    return sorted(_rel(pin_file.with_suffix(".txt")) for pin_file in _pin_files())


def _direct_pins(pin_file: Path) -> dict[str, str]:
    """name -> version of the lines of a requirements.in, which must all be exact pins."""
    pins = {}
    for raw in pin_file.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        match = PIN.fullmatch(line)
        assert match, f"{_rel(pin_file)}: pin exactly (name==X.Y.Z), found {line!r}"
        pins[_normalise(match["name"])] = match["version"]
    assert pins, f"{_rel(pin_file)}: no pin"
    return pins


def _all_direct_pins() -> dict[str, str]:
    pins: dict[str, str] = {}
    for pin_file in _pin_files():
        for name, version in _direct_pins(pin_file).items():
            assert pins.setdefault(name, version) == version, f"{name} is pinned at two versions"
    return pins


def _floor(lock: Path) -> tuple[int, ...]:
    """The lowest Python version a lock was generated for (its --python-version)."""
    match = re.search(re.escape(COMPILE) + r" (\d+)\.(\d+) -o requirements\.txt", lock.read_text())
    assert match, f"{_rel(lock)}: generate it with `{COMPILE} <X.Y> -o requirements.txt`"
    return int(match[1]), int(match[2])


def _yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text())


def _workflow_and_action_files() -> list[Path]:
    patterns = ("workflows/*.y*ml", "**/action.yml", "**/action.yaml")
    return sorted({path for pattern in patterns for path in GITHUB.glob(pattern)})


def _steps(node: Any) -> list[dict[str, Any]]:
    """Every step at any depth: workflow jobs and composite actions."""
    if isinstance(node, dict):
        own = [step for step in node.get("steps") or [] if isinstance(step, dict)]
        return own + [step for value in node.values() for step in _steps(value)]
    if isinstance(node, list):
        return [step for item in node for step in _steps(item)]
    return []


def _lines(value: Any) -> list[str]:
    return [line.strip() for line in str(value or "").splitlines() if line.strip()]


# --- hash-locked installs ------------------------------------------------------------------


def test_every_tool_lock_is_complete_and_hashed() -> None:
    """pip --require-hashes needs every package pinned and hashed, indirect ones included: the
    lock is generated from the pin, for every platform, and holds exactly the pinned versions."""
    audit = _load(ACTIONS / "security-scan" / "run-pip-audit" / "audit.py")
    for pin_file in _pin_files():
        lock = pin_file.with_suffix(".txt")
        assert lock.is_file(), f"{_rel(pin_file)} has no generated requirements.txt beside it"
        _floor(lock)
        pins = audit.complete_lock(lock)
        assert pins, (
            f"{_rel(lock)}: a line is not `name==version` with a --hash, or includes a file"
        )
        locked = {_normalise(pin.name): pin.version for _, pin in pins}
        for _, pin in pins:
            bad = [value for value in pin.hashes if not re.fullmatch(r"sha256:[0-9a-f]{64}", value)]
            assert not bad, f"{_rel(lock)}: {pin.name} has a hash that is not a sha256: {bad}"
        for name, version in _direct_pins(pin_file).items():
            assert locked.get(name) == version, (
                f"{_rel(lock)} locks {name}=={locked.get(name)} but {_rel(pin_file)} pins "
                f"{name}=={version}: regenerate the lock in the same commit"
            )


def test_every_tool_is_installed_with_require_hashes() -> None:
    """A lock only protects when pip is told to require it: the tools go through
    install-dependencies' locked-requirements, and nothing pins a tool inline."""
    action = (ACTIONS / "common" / "install-dependencies" / "action.yml").read_text()
    assert re.search(r'--require-hashes -r "\$req"\n\s+done <<< "\$LOCKED_REQUIREMENTS"', action), (
        "install-dependencies must install locked-requirements with pip --require-hashes"
    )

    installed_locked: set[str] = set()
    problems = []
    for path in _workflow_and_action_files():
        for step in _steps(_yaml(path)):
            if step.get("uses") != INSTALL_DEPENDENCIES:
                continue
            inputs = step.get("with") or {}
            for line in _lines(inputs.get("locked-requirements")):
                own = "${{ github.action_path }}/requirements.txt"
                installed_locked.add(
                    _rel(path.parent / "requirements.txt") if line == own else line
                )
            unlocked = [*_lines(inputs.get("requirements")), *_lines(inputs.get("packages"))]
            for line in unlocked:
                if "github.action_path" in line or line in _locks() or "==" in line:
                    problems.append(f"{_rel(path)}: {line!r} must go through locked-requirements")
    assert not problems, "\n".join(problems)
    missing = sorted(set(_locks()) - installed_locked)
    assert not missing, f"never installed with locked-requirements: {missing}"


def test_default_python_can_install_every_lock() -> None:
    """A lock is generated for a lowest Python version: the default of the action that installs
    it, and of install-python, must not be below it."""

    def default_python(action_file: Path) -> tuple[int, ...]:
        default = _yaml(action_file)["inputs"]["python-version"]["default"]
        return tuple(int(part) for part in str(default).split("."))

    setup = default_python(ACTIONS / "common" / "install-python" / "action.yml")
    for pin_file in _pin_files():
        lock = pin_file.with_suffix(".txt")
        action_file = pin_file.with_name("action.yml")
        default = default_python(action_file) if action_file.is_file() else setup
        assert _floor(lock) <= default, (
            f"{_rel(lock)} needs Python {_floor(lock)} or newer but its default is {default}"
        )


def test_pytest_fallback_is_the_test_tools_pin() -> None:
    """python-test.yml installs pytest into the caller's own venv when the caller has none, so
    that one pin cannot be a lock. It follows the pin Dependabot watches."""
    pinned = _direct_pins(ROOT / "tests" / "requirements.in")["pytest"]
    fallback = re.findall(r'"pytest==([^"]+)"', (WORKFLOWS / "python-test.yml").read_text())
    assert fallback == [pinned], (
        f"python-test.yml falls back to pytest=={fallback} but tests/requirements.in pins "
        f"pytest=={pinned}: move both in the same commit"
    )


# --- nothing unverified runs ---------------------------------------------------------------

DOWNLOADS = re.compile(
    r"\b(curl|wget|Invoke-WebRequest|iwr|gh\s+release\s+download"
    r"|docker\s+(run|pull)|npx|go\s+install)\b"
)


def test_no_step_downloads_an_executable() -> None:
    """Every tool comes from a hash-locked requirements file or a SHA-pinned action, so there
    is no binary whose signature must be checked. A scanner that ships as a binary would be
    fetched in a run script: this test then fails, and passes again only by being changed in
    the same pull request, next to the signature check of that download."""
    problems = []
    for path in _workflow_and_action_files():
        for step in _steps(_yaml(path)):
            script = str(step.get("run") or "")
            for match in DOWNLOADS.finditer(script):
                problems.append(f"{_rel(path)}: step {step.get('name')!r} runs `{match.group(0)}`")
    assert not problems, "\n".join(problems)


def test_inputs_reach_run_scripts_through_env() -> None:
    """The convention every action states: never an inline ${{ }} in a script."""
    problems = [
        f"{_rel(path)}: step {step.get('name')!r} expands an expression inside its run script"
        for path in _workflow_and_action_files()
        for step in _steps(_yaml(path))
        if "${{" in str(step.get("run") or "")
    ]
    assert not problems, "\n".join(problems)


# --- every pin is audited, signature-checked and watched -----------------------------------


def test_signature_policy_names_every_pinned_tool() -> None:
    """publishers.toml states, for each tool pinned in a requirements.in, who must have signed
    its files, or that upstream signs nothing. A new tool cannot be added without deciding."""
    policy = tomllib.loads(PUBLISHERS.read_text())
    signed = {_normalise(name) for name in policy.get("signed", {})}
    unsigned = {_normalise(name) for name in policy.get("unsigned", {}).get("packages", [])}
    assert not signed & unsigned, f"both signed and unsigned: {sorted(signed & unsigned)}"
    pinned = set(_all_direct_pins())
    assert signed | unsigned == pinned, (
        f"pinned but not in publishers.toml: {sorted(pinned - signed - unsigned)}; "
        f"in publishers.toml but not pinned: {sorted((signed | unsigned) - pinned)}"
    )


def test_tooling_audit_covers_every_lock() -> None:
    """self-test's tooling-audit job audits and signature-checks every lock file, and each
    vulnerability it accepts is explained in the comment above the list."""
    job = _yaml(SELF_TEST)["jobs"]["tooling-audit"]
    by_action = {str(step.get("uses", "")).rsplit("/", 1)[-1]: step for step in job["steps"]}
    for action in ("run-pip-audit", "verify-signatures"):
        assert action in by_action, f"tooling-audit has no {action} step"
        covered = sorted(_lines(by_action[action]["with"]["requirements"]))
        assert covered == _locks(), (
            f"tooling-audit's {action} step covers {covered}, the lock files are {_locks()}"
        )
    audit = by_action["run-pip-audit"]["with"]
    assert audit.get("mode") == "enforce", "tooling-audit must fail on a known vulnerability"
    text = SELF_TEST.read_text()
    for accepted in str(audit.get("ignore-vulns") or "").split():
        assert text.count(accepted) >= 2, f"{accepted} is accepted without a reason in the comment"


def test_dependabot_watches_every_lock_and_action() -> None:
    """Dependabot proposes the update of every pin: each lock's folder (uv, which regenerates
    the hashes), and each folder holding a third-party action reference."""
    updates = _yaml(GITHUB / "dependabot.yml")["updates"]

    def folders(ecosystem: str) -> list[str]:
        found: list[str] = []
        for update in updates:
            if update["package-ecosystem"] == ecosystem:
                found += [update["directory"]] if "directory" in update else update["directories"]
        return sorted(found)

    locked = sorted("/" + _rel(pin_file.parent) for pin_file in _pin_files())
    assert folders("uv") == locked, f"uv entries cover {folders('uv')}, the locks are in {locked}"
    for update in updates:
        if update["package-ecosystem"] == "uv":
            assert {"dependency-type": "all"} in update.get("allow", []), (
                f"{update['directory']}: without dependency-type all, indirect pins never move"
            )

    third_party = set()
    for path in _workflow_and_action_files():
        refs = [str(step.get("uses", "")) for step in _steps(_yaml(path))]
        refs += [str(job.get("uses", "")) for job in (_yaml(path).get("jobs") or {}).values()]
        if any(ref and not ref.startswith(("$/", "./")) for ref in refs):
            third_party.add("/" if path.parent == WORKFLOWS else "/" + _rel(path.parent))
    watched = folders("github-actions")
    assert third_party <= set(watched), (
        f"third-party actions in {sorted(third_party)}, Dependabot watches {watched}"
    )


# --- each scanner has its own mode ---------------------------------------------------------


def test_each_scanner_has_its_own_mode_and_semgrep_its_baseline() -> None:
    """One mode for everything meant a dependency with no fix could only stop blocking by
    turning the code scan off too. Each scanner follows `mode` unless its own is set, and
    pip-audit can accept a vulnerability by ID. Semgrep compares a pull request with its base."""
    workflow = _yaml(SCAN)
    inputs = workflow[True]["workflow_call"]["inputs"]  # PyYAML reads the key `on` as True
    steps = {step.get("id"): step for step in workflow["jobs"]["scan"]["steps"]}
    for scanner in ("bandit", "semgrep", "pip-audit"):
        own = f"{scanner}-mode"
        assert inputs[own]["default"] == "", f"{own} must default to empty (= same as mode)"
        step = steps[scanner]
        assert step["uses"] == f"$/.github/actions/security-scan/run-{scanner}"
        assert step["with"].get("mode") == f"${{{{ inputs.{own} || inputs.mode }}}}", (
            f"the {scanner} step must follow {own}, and `mode` only when {own} is empty"
        )
        assert f"(inputs.{own} || inputs.mode) != 'skip'" in step.get("if", ""), (
            f"the {scanner} step must be skipped by {own}: skip, whatever `mode` says"
        )

    audit = steps["pip-audit"]["with"]
    assert audit.get("ignore-vulns") == "${{ inputs.ignore-vulns }}", (
        "pip-audit must receive ignore-vulns: without it a vulnerability cannot be accepted"
    )
    assert (
        audit.get("requirements") == "${{ inputs.requirements }}"
        and inputs["requirements"]["default"] == ""
    ), "`requirements` must stay optional: empty means the action finds the files itself"
    assert audit.get("path") == "${{ inputs.project-path }}", (
        "pip-audit must search project-path for the dependency files (lock files first)"
    )

    # Semgrep runs last (it moves the checkout to the baseline and back) and gets, on a pull
    # request, the base side of the merge commit: the checkout must be deep enough to hold it.
    order = [step.get("id") for step in workflow["jobs"]["scan"]["steps"]]
    assert order[-2:] == ["semgrep", "total"], f"semgrep must be the last scanner, found {order}"
    baseline = steps["semgrep"]["with"].get("baseline-commit", "")
    assert "github.event_name == 'pull_request' && 'HEAD^1'" in baseline, (
        "on a pull request semgrep must compare with HEAD^1, the base side of the merge commit"
    )
    assert "github.event.merge_group.base_sha" in baseline, (
        "in a merge queue semgrep must compare with the commit the group is built on"
    )
    depth = steps["checkout"]["with"].get("fetch-depth")
    assert depth == "${{ github.event_name == 'merge_group' && '0' || '2' }}", (
        f"fetch-depth is {depth!r}: the baseline commit would not be in the checkout"
    )


# --- enforced mode runs the org policies as shipped ----------------------------------------

# The file an org ruleset runs on every targeted repository -> the reusable workflow it calls,
# and the only inputs it may pass: the modes of a phased rollout and, for the scan, the
# vulnerabilities the org accepts. Nothing that replaces a policy (a config, a path, a threshold).
REQUIRED_WORKFLOWS = {
    "required-python-lint.yml": ("python-lint.yml", {"mode", "mypy-mode"}),
    "required-security-scan.yml": (
        "security-scan.yml",
        {"mode", "bandit-mode", "semgrep-mode", "pip-audit-mode", "ignore-vulns"},
    ),
}


def test_required_workflows_run_the_org_policy_as_shipped() -> None:
    """Targeted repositories cannot change what enforced mode runs, so the file itself must not
    either: the reusable workflow of this same commit, on pull requests and merge groups, with
    read-only permissions, and only rollout inputs. A vulnerability accepted for every targeted
    repository needs its reason in a comment, like the ones tooling-audit accepts."""
    for name, (entry_point, rollout) in REQUIRED_WORKFLOWS.items():
        path = WORKFLOWS / name
        workflow = _yaml(path)
        assert workflow["name"] == path.stem, (
            f"{name}: the org ruleset in ENFORCEMENT.md is named after the workflow, {path.stem}"
        )
        triggers = set(workflow[True])  # PyYAML reads the key `on` as True
        assert triggers == {"pull_request", "merge_group"}, (
            f"{name} runs on {sorted(triggers)}: a required workflow runs on pull requests and "
            "merge groups, and on nothing else"
        )
        assert workflow["permissions"] == {"contents": "read"}, f"{name}: read-only permissions"
        assert len(workflow["jobs"]) == 1, f"{name}: one job, the call of {entry_point}"
        (job,) = workflow["jobs"].values()
        assert job.get("uses") == f"$/.github/workflows/{entry_point}", (
            f"{name} must call {entry_point} of this same commit ($/), found {job.get('uses')!r}"
        )
        passed = job.get("with") or {}
        assert set(passed) <= rollout, (
            f"{name} passes {sorted(set(passed) - rollout)}: enforced mode runs the org policy "
            f"as shipped, only {sorted(rollout)} may be set"
        )
        for accepted in str(passed.get("ignore-vulns") or "").split():
            assert path.read_text().count(accepted) >= 2, (
                f"{name}: {accepted} is accepted for every targeted repository without a "
                "reason in a comment"
            )


# --- self-test leaves its checkout as it found it ------------------------------------------


def test_self_test_writes_nothing_into_its_checkout() -> None:
    """What a job writes into its checkout stays there for whatever runs in it next: a staged
    fixture is a .py file self-lint would report. So the fixtures are staged under RUNNER_TEMP,
    which the runner empties around every job, and pytest runs without writing bytecode (-B)
    or its cache."""
    code = "\n".join(
        line for line in SELF_TEST.read_text().splitlines() if not line.lstrip().startswith("#")
    )
    staged = len(re.findall(r"policy-fixture", code))
    outside = len(
        re.findall(r"(?:\$RUNNER_TEMP/|\$\{\{ runner\.temp \}\}/|\*/)policy-fixture", code)
    )
    assert staged and staged == outside, (
        f"self-test.yml names policy-fixture {staged} time(s), {outside} of them under "
        "RUNNER_TEMP: stage every fixture outside the checkout"
    )
    test_runs = [
        step for step in _steps(_yaml(SELF_TEST)) if "pytest" in str(step.get("run") or "")
    ]
    assert len(test_runs) >= 2, "expected the pytest steps of lint-policy and security-policy"
    for step in test_runs:
        script = str(step["run"])
        assert " -B -m pytest " in script and "-p no:cacheprovider" in script, (
            f"step {step.get('name')!r} of self-test.yml: run pytest with -B and "
            "-p no:cacheprovider, or it writes __pycache__ and .pytest_cache into the checkout"
        )


# --- the pre-commit hooks are the tools CI runs --------------------------------------------


def _frozen(config: Path) -> dict[str, tuple[str, str]]:
    """hook repository URL -> (rev, the tag its `# frozen:` comment names)."""
    revs = FROZEN_REV.findall(config.read_text())
    repos = _yaml(config)["repos"]
    assert len(revs) == len(repos), f"{_rel(config)}: every rev needs `<full SHA>  # frozen: <tag>`"
    frozen = {}
    for repo, (rev, tag) in zip(repos, revs, strict=True):
        assert repo["rev"] == rev
        frozen[repo["repo"]] = (rev, tag)
    return frozen


def test_pre_commit_hooks_are_the_tools_ci_runs() -> None:
    """Same versions, same policy, same thresholds as CI, and every rev a full commit SHA."""
    pins = _all_direct_pins()
    policy = tomllib.loads(RUFF_POLICY.read_text())
    excluded = policy["extend-exclude"]
    # The hooks run bandit with -ll -ii, which is only CI's check while CI's defaults are medium.
    scan_inputs = _yaml(SCAN)[True]["workflow_call"]["inputs"]
    bandit_action = _yaml(ACTIONS / "security-scan" / "run-bandit" / "action.yml")["inputs"]
    for source, declared in (("security-scan.yml", scan_inputs), ("run-bandit", bandit_action)):
        thresholds = (declared["severity"]["default"], declared["confidence"]["default"])
        assert thresholds == ("medium", "medium"), (
            f"{source} defaults to severity/confidence {thresholds}: the pre-commit hooks' "
            "-ll -ii (medium, medium) must move with it"
        )

    # --no-cache, as lint.py runs ruff in CI: a hook must not leave a .ruff_cache folder in the
    # repository it checks.
    ruff_args = {
        "this repository": ["--config", _rel(RUFF_POLICY), "--no-cache"],
        "the consumer example": [
            "--isolated",
            f"--select={','.join(policy['lint']['select'])}",
            f"--line-length={policy['line-length']}",
            f"--extend-exclude={','.join(excluded)}",
            "--no-cache",
        ],
    }
    for where, config in PRE_COMMIT.items():
        frozen = _frozen(config)
        hooks = {hook["id"]: hook for repo in _yaml(config)["repos"] for hook in repo["hooks"]}
        for url, (rev, _) in frozen.items():
            assert FULL_SHA.fullmatch(rev), (
                f"{_rel(config)}: {url} rev {rev!r} is not a full commit SHA"
            )

        ruff_tag = frozen["https://github.com/astral-sh/ruff-pre-commit"][1]
        assert ruff_tag == f"v{pins['ruff']}", (
            f"{_rel(config)}: the ruff hook is {ruff_tag} but run-ruff/requirements.in pins "
            f"ruff=={pins['ruff']}: move both in the same commit"
        )
        assert hooks["ruff-check"]["args"] == ruff_args[where], (
            f"{_rel(config)}: the ruff hook of {where} must run the org policy: {ruff_args[where]}"
        )

        bandit_tag = frozen["https://github.com/PyCQA/bandit"][1]
        assert bandit_tag == pins["bandit"], (
            f"{_rel(config)}: the bandit hook is {bandit_tag} but run-bandit/requirements.in pins "
            f"bandit=={pins['bandit']}: move both in the same commit"
        )
        # -ll -ii: severity and confidence medium or higher, the thresholds asserted above.
        assert hooks["bandit"].get("args") == ["-ll", "-ii"], (
            f"{_rel(config)}: the bandit hook must run at CI's thresholds, -ll -ii"
        )
        skipped = rf"(^|/)({'|'.join(map(re.escape, excluded))})/"
        assert hooks["bandit"].get("exclude") == skipped, (
            f"{_rel(config)}: the bandit hook must skip the folders run-bandit skips: {skipped}"
        )


@pytest.mark.skipif(not ONLINE, reason="asks the hook repositories: set ORG_CI_ONLINE=1 to run it")
def test_pre_commit_revs_are_the_commits_of_the_tags_they_name() -> None:
    """A `# frozen:` comment is only a claim. The hook repository says which commit the tag is."""
    for config in PRE_COMMIT.values():
        for url, (rev, tag) in _frozen(config).items():
            refs = [f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}"]
            listing = subprocess.run(
                ["git", "ls-remote", url, *refs], capture_output=True, text=True, check=True
            ).stdout.split()
            commits = dict(zip(listing[1::2], listing[::2], strict=True))
            commit = commits.get(refs[1]) or commits.get(refs[0])  # an annotated tag's commit first
            assert commit == rev, (
                f"{_rel(config)}: {url} {tag} is commit {commit}, the rev is {rev}"
            )
