#!/usr/bin/env python3
"""Org Python type check: the implementation shipped inside the run-mypy composite action.

Runs mypy, then reports in the same GitHub Actions contract as run-ruff/lint.py:
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
import tempfile
from dataclasses import dataclass
from pathlib import Path

SUMMARY_MAX_ROWS = 200
NO_FILES_MESSAGE = "There are no .py[i] files"


@dataclass(frozen=True)
class Finding:
    file: str
    line: int
    col: int
    end_line: int
    end_col: int
    code: str
    message: str


def run_checks(target: str, config: str) -> list[Finding]:
    """Run mypy with the given config and normalise its JSON output (one object per line)."""
    with tempfile.TemporaryDirectory(prefix="org-mypy-cache-") as cache_dir:
        cmd = [sys.executable, "-m", "mypy", target, "--config-file", config]
        cmd += ["--output", "json", "--no-error-summary"]
        cmd += ["--cache-dir", cache_dir]  # throwaway cache: nothing is written into the checkout
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)

    findings = []
    unparsed = []
    for raw in proc.stdout.splitlines():
        try:
            item = json.loads(raw)
        except json.JSONDecodeError:
            unparsed.append(raw)
            continue
        if item.get("severity") != "error":
            continue  # standalone notes (e.g. reveal_type) are not findings
        line = max(item.get("line") or 1, 1)  # module-level errors report line -1
        col = max((item.get("column") or 0) + 1, 1)  # mypy columns are 0-based
        message = item["message"]
        if item.get("hint"):
            message += "\n" + item["hint"]
        findings.append(
            Finding(
                file=Path(os.path.relpath(item.get("file") or ".")).as_posix(),
                line=line,
                col=col,
                end_line=max(item.get("end_line") or line, line),
                end_col=max(item.get("end_column") or col, col),
                code=item.get("code") or "mypy",
                message=message,
            )
        )
    if unparsed:
        sys.stderr.write("\n".join(unparsed) + "\n")

    # Exit 1 = type errors. Exit 2 WITH findings = blocking errors (syntax error,
    # duplicate module): reported as findings too, like ruff's syntax errors.
    if proc.returncode == 0 or (proc.returncode in (1, 2) and findings):
        return sorted(findings, key=lambda f: (f.file, f.line, f.col, f.code))
    if proc.returncode == 2 and NO_FILES_MESSAGE in proc.stderr:
        return []  # nothing to type-check is not a failure (same as ruff)
    sys.stderr.write(proc.stderr)
    print(f"::error title=org-python-typecheck::mypy could not run (exit {proc.returncode})")
    raise SystemExit(2)


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
                f"title={_escape_property(f.code)}",
            ]
        )
        print(f"::{level} {props}::{_escape_data(f.message)}")


def write_summary(findings: list[Finding], target: str, mode: str) -> None:
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_file:
        return
    status = "passed" if not findings else ("failed" if mode == "enforce" else "reported only")
    lines = [
        "### Org Python type check",
        "",
        f"Target `{target}` · mode `{mode}` · **{len(findings)} finding(s)** · {status}",
        "",
    ]
    if findings:
        lines += ["| File | Line | Rule | Message |", "|---|---:|---|---|"]
        for f in findings[:SUMMARY_MAX_ROWS]:
            msg = f.message.replace("|", "\\|").replace("\n", " ")
            lines.append(f"| `{f.file}` | {f.line} | `{f.code}` | {msg} |")
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
    parser = argparse.ArgumentParser(description="Org Python type check")
    parser.add_argument("--path", default=".", help="directory or file to type-check")
    parser.add_argument("--mode", choices=("enforce", "report"), default="enforce")
    parser.add_argument("--config", required=True, help="mypy configuration file")
    args = parser.parse_args(argv)

    if not Path(args.path).exists():
        print(f"::error title=org-python-typecheck::path not found: {_escape_data(args.path)}")
        return 2
    if not Path(args.config).is_file():
        print(f"::error title=org-python-typecheck::config not found: {_escape_data(args.config)}")
        return 2

    findings = run_checks(args.path, args.config)

    in_actions = os.environ.get("GITHUB_ACTIONS") == "true"
    if in_actions:
        print("::group::Findings")
    for f in findings:
        print(f"{f.file}:{f.line}:{f.col}: {f.code} {f.message}")
    if in_actions:
        print("::endgroup::")
        annotate(findings, "error" if args.mode == "enforce" else "warning")

    write_summary(findings, args.path, args.mode)
    write_output("issues", str(len(findings)))
    print(f"org-python-typecheck: {len(findings)} finding(s) in '{args.path}' (mode={args.mode})")

    return 1 if findings and args.mode == "enforce" else 0


if __name__ == "__main__":
    sys.exit(main())
