#!/usr/bin/env python3
"""Signature check of the pinned tools: the implementation shipped inside verify-signatures.

pip --require-hashes guarantees that only the files hashed in a requirements.txt are installed.
This script checks where those files came from. For a file uploaded through trusted publishing,
PyPI keeps a Sigstore attestation: a statement, signed during the upload, of the repository and
workflow that built the file. For each package named in the policy (publishers.toml):

  [signed]    every hash locked for the package must belong to a file whose attestation verifies
              and was signed by a workflow of the repository the policy names;
  [unsigned]  PyPI must hold no attestation for the locked files. When upstream starts to publish
              them the check fails, so the package is moved to [signed].

No distribution is downloaded: an attestation states the sha256 of the file it covers, and that
digest is compared with the one locked here.

Reports in the GitHub Actions contract of the other scripts: annotations, a job-summary table,
the step output ``verified=<n>``, exit 1 when a check fails. Exit 2 when the checks could not be
made at all (no requirements file, an unreadable policy, or Sigstore's trust root could not be
refreshed): that is never reported as "verified". Works locally too.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import tomllib
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pypi_attestations import AttestationError, Distribution, GitHubPublisher, Provenance
from sigstore.errors import Error as SigstoreError

PYPI = "https://pypi.org"
GITHUB = "https://github.com/"
NAME = r"[A-Za-z0-9][A-Za-z0-9._-]*"
PIN = re.compile(rf"^(?P<name>{NAME})\s*(?:\[[^\]]*\])?\s*==\s*(?P<version>[^\s;\\]+)")
SHA256 = re.compile(r"--hash[=\s]+sha256:(?P<digest>[0-9a-f]{64})")


class CannotVerify(Exception):
    """Verification could not be attempted (as opposed to: a file failed it)."""


@dataclass(frozen=True)
class Result:
    package: str
    version: str
    filename: str
    ok: bool
    detail: str


def _normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def locked_hashes(files: list[Path]) -> dict[str, dict[str, set[str]]]:
    """package -> version -> sha256 digests, from hash-locked requirements files."""
    locked: dict[str, dict[str, set[str]]] = {}
    for file in files:
        requirement = ""
        for raw in [*file.read_text(encoding="utf-8").splitlines(), ""]:
            text = re.sub(r"(^|\s)#.*$", "", raw).rstrip()
            if text.endswith("\\"):
                requirement += text[:-1] + " "
                continue
            requirement = (requirement + text).strip()
            match = PIN.match(requirement)
            if match:
                digests = locked.setdefault(_normalise(match.group("name")), {}).setdefault(
                    match.group("version"), set()
                )
                digests.update(m.group("digest") for m in SHA256.finditer(requirement))
            requirement = ""
    return locked


def _get(url: str, accept: str) -> bytes:
    """GET from PyPI, the only host this script talks to. A network error is retried once."""
    if not url.startswith(f"{PYPI}/"):
        raise ValueError(f"refusing to fetch a URL outside {PYPI}: {url}")
    headers = {"Accept": accept, "User-Agent": "org-ci-verify-signatures"}
    request = urllib.request.Request(url, headers=headers)  # nosec B310 - https://pypi.org only
    for attempt in (1, 2):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:  # nosec B310
                body: bytes = response.read()
                return body
        except urllib.error.HTTPError:
            raise  # PyPI answered (404, 403, ...): asking again changes nothing
        except (urllib.error.URLError, TimeoutError):
            if attempt == 2:
                raise
            time.sleep(2)
    raise AssertionError("unreachable")


def index_files(package: str) -> dict[str, dict[str, Any]]:
    """sha256 -> file entry of the package's PyPI index (the JSON form of the simple API)."""
    raw = _get(f"{PYPI}/simple/{package}/", "application/vnd.pypi.simple.v1+json")
    entries: dict[str, dict[str, Any]] = {}
    for entry in json.loads(raw)["files"]:
        digest = entry.get("hashes", {}).get("sha256")
        if digest:
            entries[digest] = entry
    return entries


def verify_file(
    filename: str, digest: str, provenance_url: str, repository: str, offline: bool
) -> str:
    """Verify every attestation PyPI holds for one file. Returns who signed it.
    Raises ValueError (or pypi_attestations.AttestationError) when the file does not pass, and
    a sigstore error when Sigstore's trust root could not be loaded."""
    provenance = Provenance.model_validate_json(_get(provenance_url, "application/json"))
    distribution = Distribution(name=filename, digest=digest)
    signers: set[str] = set()
    for bundle in provenance.attestation_bundles:
        publisher = bundle.publisher
        if not isinstance(publisher, GitHubPublisher):
            raise ValueError(
                f"signed by a {publisher.kind} publisher, expected GitHub {repository}"
            )
        if publisher.repository.lower() != repository.lower():
            raise ValueError(f"signed by {publisher.repository}, expected {repository}")
        for attestation in bundle.attestations:
            # Sigstore verification of the signature and its certificate against this
            # publisher, then of the signed statement against this filename and digest.
            attestation.verify(publisher, distribution, offline=offline)
            signers.add(f"{publisher.repository} ({publisher.workflow})")
    if not signers:
        raise ValueError("PyPI returned no attestation for this file")
    return ", ".join(sorted(signers))


def check_package(
    package: str, versions: dict[str, set[str]], repository: str | None, offline: bool
) -> list[Result]:
    """All locked files of one package against the policy (repository None = [unsigned])."""
    results: list[Result] = []
    entries = index_files(package)
    for version in sorted(versions):
        for digest in sorted(versions[version]):
            entry = entries.get(digest)
            if entry is None:
                detail = f"sha256:{digest} is not a file of {package} on PyPI"
                results.append(Result(package, version, "?", False, detail))
                continue
            filename = str(entry["filename"])
            provenance_url = entry.get("provenance")
            if repository is None:
                ok = not provenance_url
                detail = (
                    "no attestation upstream: hash-pinned only"
                    if ok
                    else "upstream now publishes attestations: move the package to [signed]"
                )
            elif not provenance_url:
                ok, detail = False, f"no attestation on PyPI, expected one from {repository}"
            else:
                try:
                    signer = verify_file(filename, digest, str(provenance_url), repository, offline)
                    ok, detail = True, f"signed by {signer}"
                except (AttestationError, ValueError, OSError) as error:
                    # A signature that does not verify, a wrong signer, or an answer from PyPI
                    # that cannot be read: each is a failed check of this file, with its reason.
                    ok, detail = False, " ".join(f"{type(error).__name__}: {error}".split())
                except SigstoreError as error:
                    # Not about this file. A signature that does not verify is an
                    # AttestationError, above; what is left is Sigstore's trust root or services
                    # failing, which would fail every file the same way. Stop here.
                    reason = " ".join(f"{type(error).__name__}: {error}".split())
                    raise CannotVerify(reason) from error
            results.append(Result(package, version, filename, ok, detail))
    return results


def load_policy(path: Path) -> dict[str, str | None]:
    """package -> GitHub `owner/repo` that must have signed it, or None for [unsigned]."""
    policy = tomllib.loads(path.read_text(encoding="utf-8"))
    packages: dict[str, str | None] = {}
    for name, url in policy.get("signed", {}).items():
        if not isinstance(url, str) or not url.startswith(GITHUB) or url.count("/") != 4:
            raise ValueError(f"{path}: [signed] {name} must be {GITHUB}<owner>/<repository>")
        packages[_normalise(name)] = url.removeprefix(GITHUB)
    for name in policy.get("unsigned", {}).get("packages", []):
        if _normalise(name) in packages:
            raise ValueError(f"{path}: {name} is listed as both signed and unsigned")
        packages[_normalise(name)] = None
    if not packages:
        raise ValueError(f"{path}: no package listed")
    return packages


# --- GitHub Actions reporting -------------------------------------------------


def _escape_data(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_property(value: str) -> str:
    return _escape_data(value).replace(":", "%3A").replace(",", "%2C")


def write_summary(results: list[Result]) -> None:
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_file:
        return
    failed = [r for r in results if not r.ok]
    lines = [
        "### Signatures of the pinned tools",
        "",
        f"{len(results)} locked file(s) checked · **{len(failed)} failure(s)** · "
        f"{'passed' if not failed else 'failed'}",
        "",
        "| Package | Version | Locked files | Result |",
        "|---|---|---:|---|",
    ]
    groups: dict[tuple[str, str, bool, str], int] = {}
    for r in results:
        key = (r.package, r.version, r.ok, r.detail if r.ok else f"{r.filename}: {r.detail}")
        groups[key] = groups.get(key, 0) + 1
    for (package, version, ok, detail), count in sorted(groups.items()):
        text = detail.replace("|", "\\|")
        lines.append(f"| `{package}` | {version} | {count} | {'' if ok else '**FAILED** '}{text} |")
    with open(summary_file, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def write_output(name: str, value: str) -> None:
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a", encoding="utf-8") as fh:
            fh.write(f"{name}={value}\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Signature check of the pinned tools")
    parser.add_argument("--policy", required=True, help="publishers.toml")
    parser.add_argument("--requirements", required=True, help="hash-locked files, one per line")
    parser.add_argument(
        "--offline",
        action="store_true",
        help="use the Sigstore trust root shipped with the pinned sigstore: no refresh first",
    )
    args = parser.parse_args(argv)

    files = [Path(line.strip()) for line in args.requirements.splitlines() if line.strip()]
    missing = [str(file) for file in files if not file.is_file()]
    if missing or not files:
        what = ", ".join(missing) or "none given"
        print(f"::error title=org-supply-chain::requirements file not found: {_escape_data(what)}")
        return 2
    try:
        policy = load_policy(Path(args.policy))
    except (OSError, ValueError) as error:
        print(f"::error title=org-supply-chain::{_escape_data(str(error))}")
        return 2

    locked = locked_hashes(files)
    results: list[Result] = []
    for package in sorted(policy):
        versions = locked.get(package)
        if not versions:
            detail = "listed in the policy but pinned in none of the requirements files"
            results.append(Result(package, "-", "-", False, detail))
            continue
        try:
            results += check_package(package, versions, policy[package], args.offline)
        except CannotVerify as error:
            hint = (
                ""
                if args.offline
                else " Run the job again; if Sigstore stays unreachable, offline: 'true' uses "
                "the trust root shipped with the pinned sigstore."
            )
            message = f"the signatures could not be checked ({error}): nothing was verified.{hint}"
            print(f"::error title=org-supply-chain::{_escape_data(message)}")
            return 2
        except (OSError, ValueError, KeyError) as error:
            detail = f"PyPI could not be queried: {' '.join(str(error).split())}"
            results.append(Result(package, "-", "-", False, detail))

    in_actions = os.environ.get("GITHUB_ACTIONS") == "true"
    if in_actions:
        print("::group::Signature checks")
    for r in results:
        print(f"{'OK    ' if r.ok else 'FAILED'} {r.package} {r.version} {r.filename}: {r.detail}")
    if in_actions:
        print("::endgroup::")
    failed = [r for r in results if not r.ok]
    for r in failed:
        title = _escape_property(f"signature check {r.package} {r.version}")
        print(f"::error title={title}::{_escape_data(f'{r.filename}: {r.detail}')}")

    write_summary(results)
    write_output("verified", str(len(results) - len(failed)))
    print(
        f"org-supply-chain: {len(results)} locked file(s) of {len(policy)} package(s) checked, "
        f"{len(failed)} failure(s)"
    )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
