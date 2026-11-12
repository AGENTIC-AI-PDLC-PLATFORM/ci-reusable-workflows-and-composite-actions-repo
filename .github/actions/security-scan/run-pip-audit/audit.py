#!/usr/bin/env python3
"""Org dependency audit (pip-audit): the implementation shipped inside the run-pip-audit action.

Decides what to audit, runs pip-audit on it, then reports in the same GitHub Actions contract as
run-ruff/lint.py:
  * one annotation per known vulnerability,
  * a Markdown table in the job summary,
  * the step outputs ``issues=<n>``, ``audited=<what was audited>`` and ``vulnerabilities=<ids>``,
  * exit 1 in ``enforce`` mode when anything is found, exit 0 in ``report`` mode.

What is audited (the first that applies):
  1. the files given with --requirements: requirement files, or lock files named as in 3;
  2. pylock.toml / pylock.*.toml in --path: the exact locked versions (pip-audit --locked);
  3. uv.lock, poetry.lock, pdm.lock and Pipfile.lock in --path: the exact locked versions;
  4. requirements*.txt in --path;
  5. pyproject.toml in --path: pip-audit resolves the declared ranges;
  6. nothing: said with a notice, not a failure.

A requirements file whose every line carries a hash is a complete lock: all of its pins are
audited exactly as written, whatever their environment markers, and nothing is installed. Any
other requirements file is first resolved by pip-audit, in a throwaway environment.

pip-audit cannot read the lock files of uv, Poetry, PDM and Pipenv, so this script reads them:
every version they lock from a package index is audited as a pin, for every platform and every
dependency group, and nothing is installed. A package they lock from somewhere else (git, a
URL) has no index version to look up: it is listed as not audited.

A vulnerability listed with --ignore-vuln (by its ID or any alias) is accepted: pip-audit leaves
it out, and the summary says which IDs were accepted.

Works locally too: outside Actions it just prints the findings.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import tomllib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SUMMARY_MAX_ROWS = 200
NAME = r"[A-Za-z0-9][A-Za-z0-9._-]*"
VERSION = r"[A-Za-z0-9][A-Za-z0-9._+!-]*"
PIN = re.compile(rf"^(?P<name>{NAME})\s*(?:\[[^\]]*\])?\s*==\s*(?P<version>[^\s;\\]+)")
REQUIREMENT_NAME = re.compile(rf"^(?P<name>{NAME})")
HASH = re.compile(r"--hash[=\s]+(?P<hash>[A-Za-z0-9]+:[0-9A-Fa-f]+)")
# Lines that pull in other files or local code: such a file is not a self-contained lock.
INCLUDES = ("-r", "--requirement", "-c", "--constraint", "-e", "--editable")


class AuditError(Exception):
    """pip-audit could not produce a result (as opposed to: it found vulnerabilities)."""


class UnreadableLock(Exception):
    """A lock file is not in a shape this script knows (as opposed to: it locks nothing)."""


@dataclass(frozen=True)
class Pin:
    name: str
    version: str
    hashes: tuple[str, ...]


@dataclass(frozen=True)
class Finding:
    package: str
    version: str
    vuln_id: str
    aliases: tuple[str, ...]
    fix_versions: tuple[str, ...]
    file: str
    line: int


@dataclass(frozen=True)
class Locked:
    """What a lock file of uv, Poetry, PDM or Pipenv locks."""

    pins: list[Pin]
    elsewhere: list[str]  # "name (git)": locked from somewhere else than a package index


@dataclass
class Plan:
    """What will be audited: pip-audit argument lists, and where each package is declared."""

    label: str
    runs: list[list[str]] = field(default_factory=list)
    locations: dict[str, tuple[str, int]] = field(default_factory=dict)
    fallback_file: str = ""
    warnings: list[str] = field(default_factory=list)
    elsewhere: list[str] = field(default_factory=list)


def _normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _display(path: Path) -> str:
    return Path(os.path.relpath(path)).as_posix()


# --- deciding what to audit ---------------------------------------------------


def logical_lines(path: Path) -> list[tuple[int, str]]:
    """Each requirement of a requirements file as (first line number, text), comments removed
    and continuation lines joined."""
    lines: list[tuple[int, str]] = []
    buffer, start = "", 0
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        text = re.sub(r"(^|\s)#.*$", "", raw).rstrip()
        if not buffer:
            start = number
        if text.endswith("\\"):
            buffer += text[:-1] + " "
            continue
        buffer += text
        if buffer.strip():
            lines.append((start, buffer.strip()))
        buffer = ""
    if buffer.strip():
        lines.append((start, buffer.strip()))
    return lines


def complete_lock(path: Path) -> list[tuple[int, Pin]] | None:
    """The pins of a requirements file if it is a complete lock (every requirement is
    `name==version` with at least one --hash, and no other file is included), else None."""
    pins: list[tuple[int, Pin]] = []
    for number, text in logical_lines(path):
        if text.startswith("-"):
            if text.split()[0].split("=")[0] in INCLUDES:
                return None
            continue  # an index or build option: irrelevant to which versions are pinned
        match = PIN.match(text)
        hashes = tuple(m.group("hash") for m in HASH.finditer(text))
        if not match or not hashes:
            return None
        pins.append((number, Pin(match.group("name"), match.group("version"), hashes)))
    return pins or None


def layers(pins: list[Pin]) -> list[list[Pin]]:
    """Group pins so that no group holds two versions of one package: pip-audit refuses those
    in a single run, and a lock made for several platforms may contain them."""
    groups: list[dict[str, Pin]] = []
    for pin in pins:
        key = _normalise(pin.name)
        for group in groups:
            existing = group.get(key)
            if existing is None:
                group[key] = pin
                break
            if existing.version == pin.version:
                break  # the same pin again (listed in two files): audited once
        else:
            groups.append({key: pin})
    return [list(group.values()) for group in groups]


# --- the lock files of uv, Poetry, PDM and Pipenv -----------------------------------------------
#
# Each reader takes the text of a lock file and returns the versions it locks from a package
# index, and the packages it locks from somewhere else. The repository's own code (the project
# itself, a workspace member, a local folder) is neither: it is not a dependency to look up.


def _pin(name: object, version: object) -> Pin:
    """A locked package as a pin. Both values come from a file a pull request can change, and
    end up in a requirements file written for pip-audit: anything but a plain name and a plain
    version is refused."""
    if not (isinstance(name, str) and re.fullmatch(NAME, name)):
        raise UnreadableLock(f"package name {name!r}")
    if not (isinstance(version, str) and re.fullmatch(VERSION, version)):
        raise UnreadableLock(f"version {version!r} of {name}")
    return Pin(name, version, ())


def _tables(value: object, what: str) -> list[dict[str, Any]]:
    """`value` as a list of tables: [] when the key is absent."""
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise UnreadableLock(f"{what} is not a list of tables")
    return value


def _first_key(table: object, keys: tuple[str, ...]) -> str:
    return next((key for key in keys if isinstance(table, dict) and key in table), "")


def _read_uv_lock(text: str) -> Locked:
    """uv.lock: [[package]] tables with name, version and source = { <kind> = ... }."""
    data = tomllib.loads(text)
    if data.get("version") != 1:
        raise UnreadableLock(f"lock format version {data.get('version')!r} (version 1 is read)")
    locked = Locked([], [])
    for package in _tables(data.get("package"), "package"):
        source = package.get("source")
        kind = next(iter(source), "") if isinstance(source, dict) else ""
        if kind == "registry":
            locked.pins.append(_pin(package.get("name"), package.get("version")))
        elif kind not in ("virtual", "editable", "directory"):  # the repository's own code
            locked.elsewhere.append(f"{package.get('name')} ({kind or 'no source'})")
    return locked


def _read_poetry_lock(text: str) -> Locked:
    """poetry.lock: [[package]] tables with name and version, and a [package.source] table
    with its type when the package does not come from PyPI."""
    data = tomllib.loads(text)
    metadata = data.get("metadata")
    if not isinstance(metadata, dict) or "lock-version" not in metadata:
        raise UnreadableLock("no lock-version in [metadata]")
    locked = Locked([], [])
    for package in _tables(data.get("package"), "package"):
        source = package.get("source")
        kind = str(source.get("type") or "") if isinstance(source, dict) else ""
        if kind in ("", "legacy"):  # PyPI, or another package index
            locked.pins.append(_pin(package.get("name"), package.get("version")))
        elif kind != "directory":  # the repository's own code
            locked.elsewhere.append(f"{package.get('name')} ({kind})")
    return locked


def _read_pdm_lock(text: str) -> Locked:
    """pdm.lock: [[package]] tables with name and version, and a git, url or path key when the
    package does not come from a package index."""
    data = tomllib.loads(text)
    metadata = data.get("metadata")
    if not isinstance(metadata, dict) or "lock_version" not in metadata:
        raise UnreadableLock("no lock_version in [metadata]")
    locked = Locked([], [])
    for package in _tables(data.get("package"), "package"):
        kind = _first_key(package, ("git", "hg", "svn", "bzr", "url", "path"))
        if not kind:
            locked.pins.append(_pin(package.get("name"), package.get("version")))
        elif kind != "path":  # the repository's own code
            locked.elsewhere.append(f"{package.get('name')} ({kind})")
    return locked


def _read_pipfile_lock(text: str) -> Locked:
    """Pipfile.lock: JSON with the sections default and develop, each name -> its entry: a
    version ("==X"), or a git, file or path key when it does not come from a package index."""
    data = json.loads(text)
    if not isinstance(data, dict) or not isinstance(data.get("_meta"), dict):
        raise UnreadableLock("no _meta section")
    locked = Locked([], [])
    for section in ("default", "develop"):
        entries = data.get(section, {})
        if not isinstance(entries, dict):
            raise UnreadableLock(f"the {section} section is not an object")
        for name, entry in entries.items():
            kind = _first_key(entry, ("git", "hg", "svn", "bzr", "file", "path"))
            version = entry.get("version") if isinstance(entry, dict) else None
            if kind == "path":  # the repository's own code
                continue
            if kind:
                locked.elsewhere.append(f"{name} ({kind})")
            elif isinstance(version, str) and version.startswith("=="):
                locked.pins.append(_pin(name, version[2:]))
            else:
                raise UnreadableLock(f"{name} has no exact version")
    return locked


LOCK_READERS: dict[str, Callable[[str], Locked]] = {
    "uv.lock": _read_uv_lock,
    "poetry.lock": _read_poetry_lock,
    "pdm.lock": _read_pdm_lock,
    "Pipfile.lock": _read_pipfile_lock,
}
# The line on which a package's entry starts in each format (one group: its name).
TOML_ENTRY = rf'^name\s*=\s*"({NAME})"'
LOCK_ENTRY = {
    "uv.lock": TOML_ENTRY,
    "poetry.lock": TOML_ENTRY,
    "pdm.lock": TOML_ENTRY,
    "Pipfile.lock": rf'^\s{{8}}"({NAME})":\s*\{{',
}


def read_lock(path: Path) -> Locked:
    """What a lock file of uv, Poetry, PDM or Pipenv locks. Raises UnreadableLock, with the
    reason, when the file is not what its name says."""
    try:
        return LOCK_READERS[path.name](path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:  # ValueError: not TOML, not JSON, not text
        raise UnreadableLock(" ".join(str(error).split())) from error


def _locate_in(files: list[Path], pattern: str) -> dict[str, tuple[str, int]]:
    """Package name -> (file, line) for each first match of `pattern` (one group: the name)."""
    found: dict[str, tuple[str, int]] = {}
    regex = re.compile(pattern)
    for file in files:
        for number, raw in enumerate(file.read_text(encoding="utf-8").splitlines(), 1):
            match = regex.search(raw)
            if match:
                found.setdefault(_normalise(match.group(1)), (_display(file), number))
    return found


def _runs_on_pins(pins: list[Pin], flags: list[str], stem: str, workdir: Path) -> list[list[str]]:
    """One pip-audit run per layer of pins, each on a requirements file written for it."""
    runs = []
    for index, group in enumerate(layers(pins)):
        pinned = workdir / f"{stem}-{index}.txt"
        lines = (
            " ".join([f"{pin.name}=={pin.version}", *(f"--hash={h}" for h in pin.hashes)])
            for pin in group
        )
        pinned.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")
        runs.append([*flags, "-r", str(pinned)])
    return runs


def _plan_files(files: list[Path], workdir: Path) -> Plan:
    """The audit of the given files. Raises UnreadableLock for a lock file that cannot be read."""
    plan = Plan(label=", ".join(_display(f) for f in files), fallback_file=_display(files[0]))
    hashed: list[Pin] = []  # complete requirement locks
    locked: list[Pin] = []  # the lock files of uv, Poetry, PDM and Pipenv
    resolved_by_pip_audit: list[Path] = []
    for file in files:
        if file.name in LOCK_READERS:
            try:
                packages = read_lock(file)
            except UnreadableLock as error:
                raise UnreadableLock(f"{_display(file)}: {error}") from error
            locked += packages.pins
            plan.elsewhere += packages.elsewhere
            for name, where in _locate_in([file], LOCK_ENTRY[file.name]).items():
                plan.locations.setdefault(name, where)
            continue
        pins = complete_lock(file)
        if pins is None:
            resolved_by_pip_audit.append(file)
            for number, text in logical_lines(file):
                match = REQUIREMENT_NAME.match(text)
                if match:
                    plan.locations.setdefault(
                        _normalise(match.group("name")), (_display(file), number)
                    )
            continue
        for number, pin in pins:
            hashed.append(pin)
            plan.locations.setdefault(_normalise(pin.name), (_display(file), number))

    # Exact versions: every pin, markers dropped, nothing resolved and nothing installed.
    plan.runs += _runs_on_pins(hashed, ["--require-hashes", "--disable-pip"], "locked", workdir)
    plan.runs += _runs_on_pins(locked, ["--no-deps", "--disable-pip"], "pinned", workdir)
    if resolved_by_pip_audit:
        plan.runs.append([arg for file in resolved_by_pip_audit for arg in ("-r", str(file))])
    return plan


def make_plan(path: Path, requirements: list[str], workdir: Path) -> Plan:
    """Decide what to audit. Raises AuditError when the request cannot be met."""
    if requirements:
        files = [Path(name) for name in requirements]
        missing = [str(file) for file in files if not file.is_file()]
        if missing:
            raise AuditError(f"requirements file not found: {', '.join(missing)}")
        try:
            return _plan_files(files, workdir)
        except UnreadableLock as error:
            raise AuditError(f"lock file not readable: {error}") from error

    if not path.is_dir():
        raise AuditError(f"path is not a directory: {path}")

    pylocks = sorted({*path.glob("pylock.toml"), *path.glob("pylock.*.toml")})
    requirement_files = sorted(f for f in path.glob("requirements*.txt") if f.is_file())
    pyproject = path / "pyproject.toml"
    if pylocks:
        return Plan(
            label=", ".join(_display(f) for f in pylocks),
            runs=[["--locked", str(path)]],
            locations=_locate_in(pylocks, rf'^\s*name\s*=\s*"({NAME})"'),
            fallback_file=_display(pylocks[0]),
        )

    locks: list[Path] = []
    unreadable: list[str] = []
    for lock in (path / name for name in LOCK_READERS if (path / name).is_file()):
        try:
            read_lock(lock)
        except UnreadableLock as error:
            unreadable.append(f"{lock.name} ({error})")
        else:
            locks.append(lock)

    # The first source that gives something to audit. A lock that holds no package from an
    # index (a project without dependencies) does not end the search.
    plan = Plan(label="")
    elsewhere: list[str] = []
    for files in (locks, requirement_files):
        if files and not plan.runs:
            plan = _plan_files(files, workdir)
            elsewhere += plan.elsewhere
    if not plan.runs and pyproject.is_file():
        plan = Plan(
            label=_display(pyproject),
            runs=[[str(path)]],
            locations=_locate_in([pyproject], rf'^\s*["\']({NAME})'),
            fallback_file=_display(pyproject),
        )
    if not plan.runs:
        plan = Plan(label="")
    plan.elsewhere = elsewhere

    if unreadable:
        found = f"{', '.join(unreadable)} in '{path}' could not be read"
        if not plan.runs:
            # A lock that cannot be read is not "no dependencies".
            raise AuditError(f"{found}, and there is no other dependency file to audit")
        plan.warnings.append(
            f"{found}: {plan.label} was audited instead. This action reads uv.lock (format "
            "version 1), poetry.lock, pdm.lock and Pipfile.lock; for any other lock, commit a "
            "pylock.toml or pass requirement files."
        )
    return plan


# --- running pip-audit --------------------------------------------------------


def run_pip_audit(
    run: list[str], ignore: list[str], workdir: Path
) -> tuple[list[dict[str, object]], str]:
    """One pip-audit run. Returns its `dependencies` list and what it printed.
    Raises AuditError unless pip-audit produced a report."""
    report_file = workdir / "report.json"
    report_file.unlink(missing_ok=True)
    cmd = [sys.executable, "-m", "pip_audit", "--progress-spinner", "off", "--desc", "off"]
    cmd += ["-f", "json", "-o", str(report_file)]
    for vuln_id in ignore:
        cmd += ["--ignore-vuln", vuln_id]
    proc = subprocess.run(cmd + run, capture_output=True, text=True, check=False)
    log = (proc.stdout + proc.stderr).strip()

    dependencies: list[dict[str, object]] | None = None
    try:
        report = json.loads(report_file.read_text(encoding="utf-8"))
        dependencies = report["dependencies"]
    except (OSError, ValueError, KeyError, TypeError):
        dependencies = None
    # pip-audit exits 1 both for vulnerabilities and for its own errors: it is a result only
    # if it wrote the report, and exit 1 must come with at least one vulnerability in it.
    has_vulns = any(dep.get("vulns") for dep in dependencies or [])
    if dependencies is None or proc.returncode not in (0, 1) or (proc.returncode == 1) != has_vulns:
        raise AuditError(f"pip-audit exited {proc.returncode}\n{log}")
    return dependencies, log


def collect(dependencies: list[dict[str, object]], plan: Plan) -> tuple[list[Finding], list[str]]:
    """Findings and skipped packages of one pip-audit report."""
    findings: list[Finding] = []
    skipped: list[str] = []
    for dep in dependencies:
        name = str(dep.get("name", ""))
        if dep.get("skip_reason"):
            skipped.append(f"{name}: {dep['skip_reason']}")
            continue
        file, line = plan.locations.get(_normalise(name), (plan.fallback_file, 1))
        vulns = dep.get("vulns")
        for vuln in vulns if isinstance(vulns, list) else []:
            findings.append(
                Finding(
                    package=name,
                    version=str(dep.get("version", "")),
                    vuln_id=str(vuln["id"]),
                    aliases=tuple(sorted(vuln.get("aliases") or [])),
                    fix_versions=tuple(vuln.get("fix_versions") or []),
                    file=file,
                    line=line,
                )
            )
    return findings, skipped


def _describe(f: Finding) -> str:
    aliases = f" ({', '.join(f.aliases)})" if f.aliases else ""
    fixed = f"fixed in {', '.join(f.fix_versions)}" if f.fix_versions else "no fixed version yet"
    return f"{f.package} {f.version}: {f.vuln_id}{aliases}, {fixed}"


# --- GitHub Actions reporting -------------------------------------------------


def _escape_data(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_property(value: str) -> str:
    return _escape_data(value).replace(":", "%3A").replace(",", "%2C")


def annotate(findings: list[Finding], level: str) -> None:
    for f in findings:
        title = f"pip-audit {f.vuln_id} ({f.package} {f.version})"
        props = [f"title={_escape_property(title)}"]
        if f.file:
            props = [f"file={_escape_property(f.file)}", f"line={f.line}", *props]
        print(f"::{level} {','.join(props)}::{_escape_data(_describe(f))}")


def write_summary(
    findings: list[Finding], plan: Plan, mode: str, ignore: list[str], skipped: list[str]
) -> None:
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_file:
        return
    lines = ["### Dependency audit (pip-audit)", ""]
    if not plan.runs:
        lines.append("No dependency file found: nothing was audited.")
    else:
        status = "passed" if not findings else ("failed" if mode == "enforce" else "reported only")
        packages = len({(f.package.lower(), f.version) for f in findings})
        plural = "y" if len(findings) == 1 else "ies"
        lines.append(
            f"Audited `{plan.label}` · mode `{mode}` · **{len(findings)} known "
            f"vulnerabilit{plural}** in {packages} package(s) · {status}"
        )
    lines.append("")
    if findings:
        lines += ["| Package | Version | ID | Aliases | Fixed in |", "|---|---|---|---|---|"]
        for f in findings[:SUMMARY_MAX_ROWS]:
            lines.append(
                f"| `{f.package}` | {f.version} | `{f.vuln_id}` | {', '.join(f.aliases) or '-'} "
                f"| {', '.join(f.fix_versions) or '-'} |"
            )
        if len(findings) > SUMMARY_MAX_ROWS:
            lines.append(f"\n… and {len(findings) - SUMMARY_MAX_ROWS} more (see the job log).")
        lines.append("")
    if ignore:
        lines += [
            f"Accepted with ignore-vulns, not reported: {', '.join(f'`{i}`' for i in ignore)}",
            "",
        ]
    if skipped:
        lines += ["Not audited (pip-audit skipped them):", *[f"- {item}" for item in skipped], ""]
    if plan.elsewhere:
        lines += [
            "Not audited (locked from somewhere else than a package index, so there is no "
            "index version to look up):",
            *[f"- {item}" for item in plan.elsewhere],
            "",
        ]
    lines += [f"> {warning}" for warning in plan.warnings]
    with open(summary_file, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines).rstrip() + "\n")


def write_output(name: str, value: str) -> None:
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a", encoding="utf-8") as fh:
            fh.write(f"{name}={value}\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Org dependency audit (pip-audit)")
    parser.add_argument("--path", default=".", help="directory searched for dependency files")
    parser.add_argument(
        "--requirements",
        default="",
        help="requirement or lock files, one per line (replaces the search)",
    )
    parser.add_argument(
        "--ignore-vuln", default="", help="accepted vulnerability IDs, separated by whitespace"
    )
    parser.add_argument("--mode", choices=("enforce", "report"), default="enforce")
    args = parser.parse_args(argv)

    requirements = [line.strip() for line in args.requirements.splitlines() if line.strip()]
    ignore = (
        sorted(set(re.split(r"[\s,]+", args.ignore_vuln.strip())))
        if args.ignore_vuln.strip()
        else []
    )
    in_actions = os.environ.get("GITHUB_ACTIONS") == "true"

    with tempfile.TemporaryDirectory(prefix="org-pip-audit-") as tmp:
        workdir = Path(tmp)
        findings: list[Finding] = []
        skipped: list[str] = []
        try:
            plan = make_plan(Path(args.path), requirements, workdir)
            for run in plan.runs:
                dependencies, log = run_pip_audit(run, ignore, workdir)
                if log:
                    print(log)
                found, not_audited = collect(dependencies, plan)
                findings += found
                skipped += not_audited
        except AuditError as error:
            # A report that could not be produced is not "no vulnerabilities": it fails the
            # step in enforce mode. In report mode it only warns, like a finding would.
            print(error, file=sys.stderr)
            first_line = _escape_data(str(error).splitlines()[0])
            if args.mode == "report":
                print(
                    "::warning title=org-security-scan::pip-audit could not audit: "
                    f"{first_line} (report mode: not failing the step)"
                )
                return 0
            print(f"::error title=org-security-scan::pip-audit could not audit: {first_line}")
            return 2

    # pip-audit lists an advisory once per alias set: one finding per package, version and ID.
    unique = {(f.package.lower(), f.version, f.vuln_id): f for f in findings}
    findings = sorted(unique.values(), key=lambda f: (f.package.lower(), f.version, f.vuln_id))
    skipped = sorted(set(skipped))

    for warning in plan.warnings:
        print(f"::warning title=org-security-scan::{_escape_data(warning)}")
    if not plan.runs:
        print(
            "::notice title=org-security-scan::no dependency to audit found in "
            f"'{_escape_data(args.path)}' (pylock.toml, uv.lock, poetry.lock, pdm.lock, "
            "Pipfile.lock, requirements*.txt, pyproject.toml)"
        )
    if ignore:
        print(
            "::notice title=org-security-scan::pip-audit does not report these accepted "
            f"vulnerabilities (ignore-vulns): {_escape_data(', '.join(ignore))}"
        )

    if in_actions:
        print("::group::Findings")
    for f in findings:
        print(f"{f.file}:{f.line}: {_describe(f)}")
    for item in skipped:
        print(f"not audited: {item}")
    for item in plan.elsewhere:
        print(f"not audited: {item}: not locked from a package index")
    if in_actions:
        print("::endgroup::")
        annotate(findings, "error" if args.mode == "enforce" else "warning")

    write_summary(findings, plan, args.mode, ignore, skipped)
    write_output("issues", str(len(findings)))
    write_output("audited", plan.label)
    write_output("vulnerabilities", " ".join(sorted({f.vuln_id for f in findings})))
    print(
        f"org-security-scan: pip-audit reported {len(findings)} known vulnerabilit"
        f"{'y' if len(findings) == 1 else 'ies'} in '{plan.label or 'nothing'}' (mode={args.mode})"
    )

    return 1 if findings and args.mode == "enforce" else 0


if __name__ == "__main__":
    sys.exit(main())
