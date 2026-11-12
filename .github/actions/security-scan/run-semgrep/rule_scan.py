#!/usr/bin/env python3
"""Org code scan (semgrep): the implementation shipped inside the run-semgrep composite action.

Runs semgrep with the organization's rules (rules/ next to this file), then reports in the same
GitHub Actions contract as run-ruff/lint.py:
  * one annotation per finding (shown inline on the pull request diff),
  * a Markdown table in the job summary,
  * the step output ``issues=<n>``,
  * exit 1 in ``enforce`` mode when anything is found, exit 0 in ``report`` mode.

With --baseline-commit, semgrep also scans that commit and reports only the findings that are
not already in it: on a pull request, the ones the pull request adds. Without it, every finding
in the target is reported.

Nothing leaves the machine: the rules are local files, and metrics and the version check are off.

Works locally too: outside Actions it just prints the findings.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

SUMMARY_MAX_ROWS = 200
# Same exclusions as the org lint policy (ruff.toml). Semgrep adds its own defaults (tests/,
# node_modules/, ...) unless the repository has a .semgrepignore, and skips what git ignores.
EXCLUDE = (".venv", "build", "dist", "migrations")
RULE_ID = re.compile(r"^\s*-\s+id:\s*(\S+)\s*$", re.MULTILINE)


@dataclass(frozen=True)
class Finding:
    file: str
    line: int
    col: int
    end_line: int
    end_col: int
    code: str
    severity: str
    message: str


def _fail(message: str) -> SystemExit:
    print(f"::error title=org-security-scan::{_escape_data(message)}")
    return SystemExit(2)


def semgrep_executable() -> str:
    """The semgrep installed next to the running interpreter (`python -m semgrep` is deprecated)."""
    found = shutil.which("semgrep", path=os.fspath(Path(sys.executable).parent))
    if not found:
        raise _fail(f"semgrep is not installed next to {sys.executable}")
    return found


def rule_ids(config: Path) -> list[str]:
    """The ids declared in the rule files, longest first."""
    files = (
        [config] if config.is_file() else sorted({*config.rglob("*.yml"), *config.rglob("*.yaml")})
    )
    ids = {rule for file in files for rule in RULE_ID.findall(file.read_text(encoding="utf-8"))}
    return sorted(ids, key=lambda rule: (-len(rule), rule))


def resolve_baseline(revision: str) -> str:
    """The commit SHA of `revision`. The commit must already be in the local repository."""
    proc = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", f"{revision}^{{commit}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        raise _fail(
            f"baseline commit '{revision}' is not in this checkout: run inside the git "
            "repository and fetch enough history (actions/checkout fetch-depth)"
        )
    return proc.stdout.strip()


def run_checks(target: str, config: str, baseline: str) -> tuple[list[Finding], int, list[str]]:
    """Run semgrep and normalise its JSON report: findings, files scanned, scan problems."""
    known = rule_ids(Path(config))
    with tempfile.TemporaryDirectory(prefix="org-semgrep-") as tmp:
        report_file = Path(tmp) / "report.json"  # outside the checkout: it must stay clean
        cmd = [semgrep_executable(), "scan", "--config", config]
        cmd += ["--metrics", "off", "--disable-version-check"]
        cmd += ["--quiet", "--json", "--output", str(report_file)]
        for pattern in EXCLUDE:
            cmd += ["--exclude", pattern]
        if baseline:
            cmd += ["--baseline-commit", baseline]
        cmd.append(target)
        # For the baseline, semgrep moves the checkout to that commit and back. Git LFS must
        # not try to download the files that differ: CI checkouts keep no credentials.
        env = {**os.environ, "GIT_LFS_SKIP_SMUDGE": "1"}
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False, env=env)
        try:
            report = json.loads(report_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            report = None
    # Without --error, semgrep exits 0 whether or not it finds anything: any other exit, or no
    # report, means semgrep itself failed (invalid rule, unknown baseline, ...).
    if proc.returncode != 0 or not isinstance(report, dict):
        sys.stderr.write(proc.stdout + proc.stderr)
        raise _fail(f"semgrep could not run (exit {proc.returncode})")

    findings = []
    for item in report.get("results", []):
        check_id = item["check_id"]
        # Semgrep prefixes each id with the path of its rule file: report the id as declared.
        code = next((r for r in known if check_id == r or check_id.endswith("." + r)), check_id)
        start, end = item["start"], item["end"]
        findings.append(
            Finding(
                file=Path(os.path.relpath(item["path"])).as_posix(),
                line=start["line"],
                col=start["col"],
                end_line=end["line"],
                end_col=end["col"],
                code=code,
                severity=item["extra"].get("severity", ""),
                message=" ".join(item["extra"]["message"].split()),
            )
        )
    scanned = len(report.get("paths", {}).get("scanned", []))
    problems = [
        f"{error.get('level', 'error')}: {' '.join(str(error.get('message', '')).split())}"
        for error in report.get("errors", [])
    ]
    return sorted(findings, key=lambda f: (f.file, f.line, f.col, f.code)), scanned, problems


def _label(finding: Finding) -> str:
    return f"{finding.code} ({finding.severity})" if finding.severity else finding.code


# --- GitHub Actions reporting -------------------------------------------------


def _escape_data(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_property(value: str) -> str:
    return _escape_data(value).replace(":", "%3A").replace(",", "%2C")


def annotate(findings: list[Finding], level: str) -> None:
    for f in findings:
        props = ",".join(
            [
                f"file={_escape_property(f.file)}",
                f"line={f.line}",
                f"endLine={f.end_line}",
                f"col={f.col}",
                f"endColumn={f.end_col}",
                f"title={_escape_property('semgrep ' + _label(f))}",
            ]
        )
        print(f"::{level} {props}::{_escape_data(f.message)}")


def write_summary(
    findings: list[Finding], target: str, mode: str, baseline: str, scanned: int, problems: int
) -> None:
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_file:
        return
    status = "passed" if not findings else ("failed" if mode == "enforce" else "reported only")
    scope = f"new since `{baseline[:12]}`" if baseline else "full scan"
    lines = [
        "### Code scan (semgrep)",
        "",
        f"Target `{target}` · {scanned} file(s) scanned · {scope} · mode `{mode}` · "
        f"**{len(findings)} finding(s)** · {status}",
        "",
    ]
    if findings:
        lines += ["| File | Line | Rule | Severity | Message |", "|---|---:|---|---|---|"]
        for f in findings[:SUMMARY_MAX_ROWS]:
            msg = f.message.replace("|", "\\|").replace("\n", " ")
            lines.append(f"| `{f.file}` | {f.line} | `{f.code}` | {f.severity or '-'} | {msg} |")
        if len(findings) > SUMMARY_MAX_ROWS:
            lines.append(f"\n… and {len(findings) - SUMMARY_MAX_ROWS} more (see the job log).")
    if problems:
        lines += ["", f"Semgrep reported {problems} scan problem(s): see the job log."]
    with open(summary_file, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def write_output(name: str, value: str) -> None:
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a", encoding="utf-8") as fh:
            fh.write(f"{name}={value}\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Org code scan (semgrep)")
    parser.add_argument("--path", default=".", help="directory or file to scan")
    parser.add_argument("--mode", choices=("enforce", "report"), default="enforce")
    parser.add_argument("--config", required=True, help="semgrep rules (file or directory)")
    parser.add_argument(
        "--baseline-commit",
        default="",
        help="git revision: report only the findings that are not already in it",
    )
    args = parser.parse_args(argv)

    if not Path(args.path).exists():
        print(f"::error title=org-security-scan::path not found: {_escape_data(args.path)}")
        return 2
    if not Path(args.config).exists():
        print(f"::error title=org-security-scan::rules not found: {_escape_data(args.config)}")
        return 2

    baseline = resolve_baseline(args.baseline_commit) if args.baseline_commit else ""
    findings, scanned, problems = run_checks(args.path, args.config, baseline)

    in_actions = os.environ.get("GITHUB_ACTIONS") == "true"
    for problem in problems:
        print(f"semgrep {problem}", file=sys.stderr)
    if in_actions:
        print("::group::Findings")
    for f in findings:
        print(f"{f.file}:{f.line}:{f.col}: {_label(f)} {f.message}")
    if in_actions:
        print("::endgroup::")
        annotate(findings, "error" if args.mode == "enforce" else "warning")

    write_summary(findings, args.path, args.mode, baseline, scanned, len(problems))
    write_output("issues", str(len(findings)))
    scope = f"new since {baseline[:12]}" if baseline else "full scan"
    print(
        f"org-security-scan: semgrep reported {len(findings)} finding(s) in '{args.path}' "
        f"({scope}, mode={args.mode})"
    )

    return 1 if findings and args.mode == "enforce" else 0


if __name__ == "__main__":
    sys.exit(main())
