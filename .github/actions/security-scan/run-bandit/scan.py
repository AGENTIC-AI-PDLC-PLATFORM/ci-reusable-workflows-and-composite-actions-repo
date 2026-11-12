#!/usr/bin/env python3
"""Org code scan (bandit): the implementation shipped inside the run-bandit composite action.

Runs bandit, then reports in the same GitHub Actions contract as run-ruff/lint.py:
  * one annotation per finding (shown inline on the pull request diff),
  * a Markdown table in the job summary,
  * the step output ``issues=<n>``,
  * exit 1 in ``enforce`` mode when anything is found, exit 0 in ``report`` mode.

Works locally too: outside Actions it just prints the findings.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

SUMMARY_MAX_ROWS = 200
LEVELS = ("low", "medium", "high")
# Same exclusions as the org lint policy (ruff.toml), as the path fragments bandit matches.
EXCLUDE = "/.venv/,/build/,/dist/,/migrations/"


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


def run_checks(target: str, severity: str, confidence: str) -> list[Finding]:
    """Run bandit at the given thresholds and normalise its JSON report."""
    cmd = [sys.executable, "-m", "bandit", "-r", target, "-q", "-x", EXCLUDE]
    cmd += ["--severity-level", severity, "--confidence-level", confidence]
    cmd += ["-f", "json"]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)

    # Exit 0 = nothing to report, exit 1 = findings or files bandit could not parse. Any other
    # exit, or output that is not the JSON report, means bandit itself failed.
    report = None
    if proc.returncode in (0, 1):
        try:
            report = json.loads(proc.stdout)
        except json.JSONDecodeError:
            report = None
    if not isinstance(report, dict):
        sys.stderr.write(proc.stderr)
        print(f"::error title=org-security-scan::bandit could not run (exit {proc.returncode})")
        raise SystemExit(2)

    findings = []
    for item in report.get("results", []):
        line = max(item.get("line_number") or 1, 1)
        col = max((item.get("col_offset") or 0) + 1, 1)
        findings.append(
            Finding(
                file=Path(os.path.relpath(item["filename"])).as_posix(),
                line=line,
                col=col,
                end_line=max([line, *item.get("line_range", [])]),
                end_col=max((item.get("end_col_offset") or 0) + 1, col),
                code=item["test_id"],
                severity=item["issue_severity"],
                message=item["issue_text"],
            )
        )
    # A file bandit cannot parse was not scanned: reported as a finding, like the syntax
    # errors of ruff and mypy.
    for item in report.get("errors", []):
        findings.append(
            Finding(
                file=Path(os.path.relpath(item["filename"])).as_posix(),
                line=1,
                col=1,
                end_line=1,
                end_col=1,
                code="syntax-error",
                severity="",
                message=f"not scanned: {item.get('reason') or 'bandit could not parse this file'}",
            )
        )
    return sorted(findings, key=lambda f: (f.file, f.line, f.col, f.code))


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
                f"title={_escape_property('bandit ' + _label(f))}",
            ]
        )
        print(f"::{level} {props}::{_escape_data(f.message)}")


def write_summary(
    findings: list[Finding], target: str, severity: str, confidence: str, mode: str
) -> None:
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_file:
        return
    status = "passed" if not findings else ("failed" if mode == "enforce" else "reported only")
    lines = [
        "### Code scan (bandit)",
        "",
        f"Target `{target}` · severity ≥ `{severity}` · confidence ≥ `{confidence}` · "
        f"mode `{mode}` · **{len(findings)} finding(s)** · {status}",
        "",
    ]
    if findings:
        lines += ["| File | Line | Rule | Severity | Message |", "|---|---:|---|---|---|"]
        for f in findings[:SUMMARY_MAX_ROWS]:
            msg = f.message.replace("|", "\\|").replace("\n", " ")
            lines.append(f"| `{f.file}` | {f.line} | `{f.code}` | {f.severity or '-'} | {msg} |")
        if len(findings) > SUMMARY_MAX_ROWS:
            lines.append(f"\n… and {len(findings) - SUMMARY_MAX_ROWS} more (see the job log).")
    with open(summary_file, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def write_output(name: str, value: str) -> None:
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a", encoding="utf-8") as fh:
            fh.write(f"{name}={value}\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Org code scan (bandit)")
    parser.add_argument("--path", default=".", help="directory or file to scan")
    parser.add_argument("--mode", choices=("enforce", "report"), default="enforce")
    parser.add_argument("--severity", choices=LEVELS, default="medium", help="lowest severity")
    parser.add_argument("--confidence", choices=LEVELS, default="medium", help="lowest confidence")
    args = parser.parse_args(argv)

    # bandit exits 0 on a missing path: checked here so a typo cannot pass silently.
    if not Path(args.path).exists():
        print(f"::error title=org-security-scan::path not found: {_escape_data(args.path)}")
        return 2

    findings = run_checks(args.path, args.severity, args.confidence)

    in_actions = os.environ.get("GITHUB_ACTIONS") == "true"
    if in_actions:
        print("::group::Findings")
    for f in findings:
        print(f"{f.file}:{f.line}:{f.col}: {_label(f)} {f.message}")
    if in_actions:
        print("::endgroup::")
        annotate(findings, "error" if args.mode == "enforce" else "warning")

    write_summary(findings, args.path, args.severity, args.confidence, args.mode)
    write_output("issues", str(len(findings)))
    print(
        f"org-security-scan: bandit reported {len(findings)} finding(s) in '{args.path}' "
        f"(severity>={args.severity}, confidence>={args.confidence}, mode={args.mode})"
    )

    return 1 if findings and args.mode == "enforce" else 0


if __name__ == "__main__":
    sys.exit(main())
