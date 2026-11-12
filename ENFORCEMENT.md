# How the versioning promise is enforced

ruff.toml and mypy.ini open with the same sentence:

> Versioned together with lint.py (typecheck.py) and action.yml: a rule change ships in the same
> commit as the code; repos pinned to a SHA move deliberately.

| Clause | Enforced by | Fails loudly when |
|---|---|---|
| Versioned together with the script and action.yml | `$/` for every internal `uses:`, `$GITHUB_ACTION_PATH` for the scripts, policies and requirements: the caller's single ref selects all of them | By construction. `test_every_uses_is_this_commit_or_a_full_sha` fails on a `./` or by-name self-reference that would break it |
| … including ruff itself | `required-version` in ruff.toml, equal to the pin in run-ruff/requirements.txt | Ruff exits 2 under any other version. `test_ruff_pin_and_required_version_agree` fails when the two pins differ |
| … including mypy itself | mypy has no `required-version` setting, so a test plays that role | `test_mypy_pin_is_the_mypy_that_runs` fails when the installed mypy is not the pin in run-mypy/requirements.txt |
| … including bandit, pip-audit and semgrep | Each is pinned in the `requirements.in` of its action. None has a `required-version` setting, so tests play that role | `test_bandit_pin_is_the_bandit_that_runs`, `test_pip_audit_pin_is_the_pip_audit_that_runs` and `test_semgrep_pin_is_the_semgrep_that_runs` fail when the scanner that runs is not its pin |
| … and every file pip installs for them | Each `requirements.txt` is a complete lock generated from its `requirements.in` (every package, its sha256 hashes), installed with `pip --require-hashes` | pip refuses an unpinned or unhashed line, and any download whose sha256 is not in the file. `test_every_tool_lock_is_complete_and_hashed` and `test_every_tool_is_installed_with_require_hashes` fail when a lock is incomplete, differs from its pin, or is installed any other way |
| … and every third-party action underneath | Full 40-character commit SHAs | The same `uses:` test fails on any tag or branch ref |
| A rule change ships in the same commit as the code | `main` takes only squash merges of PRs approved by code owners, whose `lint-policy` and `self-lint` checks passed on an up-to-date branch | `test_ruff_findings_match_expected` and `test_mypy_findings_match_expected` fail when findings change without `tests/policy/<tool>/expected.txt`. `self-lint` fails when this repo's own code breaks a new rule. The fixture steps fail when an action stops reporting what its policy finds |
| … for the security scans as for lint | The `security-policy` and `self-scan` checks, required like the two above | `test_bandit_findings_match_expected` and `test_semgrep_findings_match_expected` fail when findings change without `tests/policy/<tool>/expected.txt`. `test_every_semgrep_rule_has_a_case_in_the_fixtures` fails for a rule no fixture exercises. `self-scan` fails when this repo's own scripts, workflows or actions break a rule. The fixture steps fail when an action stops reporting what its scanner finds |
| Repos pinned to a SHA move deliberately | Opt-in repos pin a full SHA and Dependabot proposes each move as a PR that runs the new policy. Enforced mode pins the org ruleset to a SHA | See [What is still not enforced](#what-is-still-not-enforced) |
| Enforced mode runs the policies as shipped | `required-python-lint.yml` and `required-security-scan.yml` call the reusable workflow of their own commit and pass nothing that replaces a policy | `test_required_workflows_run_the_org_policy_as_shipped` fails when one passes anything but the modes of a phased rollout, runs on another event, or accepts a vulnerability without a reason in a comment |

Squash-only is what makes "same commit" literal. With merge or rebase merges, every commit of a
multi-commit PR lands on `main`, including one where a policy changed and its script did not
yet. A caller, Dependabot or the org ruleset could pin that commit.

The fixtures cover every selected ruff family except E9 (a syntax error would stop ruff parsing
the rest), and both mypy.ini settings: dropping `check_untyped_defs` removes a finding, dropping
`ignore_missing_imports` adds one.

The security fixtures follow the same idea: every reported line sits next to a safe one. Bandit's
fixture has a low-severity line and a low-confidence line that the org thresholds keep silent
(`test_bandit_thresholds_are_what_keeps_the_rest_silent`), and a `# nosec` line. Every semgrep
rule, and every kind of input its taint rules treat as untrusted, has a case. pip-audit's
expected list is a minimum, because new advisories keep being published for an old version.
Its lock fixtures are the lock files uv, Poetry, PDM and Pipenv wrote for one project, with a
package behind a marker, one in a dev group, and one each from git, a URL and a local folder:
`locked.txt` lists what `audit.py` must read from every one of them.

A fixture is stored with a `.txt` suffix and gets its real name only when a test or a job runs,
and never inside the checkout: the two jobs that run the actions on the fixtures stage them
under `RUNNER_TEMP`, which the runner empties around every job, and pytest runs with `-B` and
without its cache. A job that left a fixture in its checkout would make whatever lints that
checkout next report it. `test_self_test_writes_nothing_into_its_checkout` fails when a
fixture is staged in the checkout again, or when pytest may write there.

Third-party actions are pinned to what `@v7` resolved to on 2026-11-03:
`actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1` (v7.0.1) and
`actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0` (v7.1.0).

## The tools are dependencies too

Every repository that calls this one runs the tools pinned here, so the pins are held to what the
scanners ask of anyone's dependencies.

| Statement | Enforced by | Fails loudly when |
|---|---|---|
| No pinned tool has a known vulnerability | `tooling-audit` runs pip-audit on every pin of every lock, on each pull request and every week | The job fails on an advisory that is not in its `ignore-vulns` list. `test_tooling_audit_covers_every_lock` fails when a lock is missing from the job, or an accepted ID has no reason in the comment above the list |
| The pinned files were built by their upstream | `tooling-audit` runs `verify-signatures`: for each tool in `publishers.toml`, every locked file must carry a PyPI attestation that verifies (Sigstore) and was signed by a workflow of the named repository | The job fails on a missing or invalid attestation, another signer, or a locked hash that is not a file of that package. `test_signature_policy_names_every_pinned_tool` fails when a pinned tool is in neither table of `publishers.toml` |
| No tool is fetched as an unverified binary | Every tool comes from a hash-locked requirements file or a SHA-pinned action | `test_no_step_downloads_an_executable` fails on a `curl`, `wget`, `gh release download`, `docker run` and the like in any run script |
| Every pin has an update path | `.github/dependabot.yml`: one `uv` entry per lock (Dependabot regenerates the hashes), and the folders holding third-party actions | `test_dependabot_watches_every_lock_and_action` fails when a lock or a third-party action is not covered |
| The pre-commit hooks are the tools CI runs | Each `rev` is a full commit SHA whose `# frozen:` tag equals the CI pin; the hooks pass the org policy and thresholds | `test_pre_commit_hooks_are_the_tools_ci_runs`, and `test_pre_commit_revs_are_the_commits_of_the_tags_they_name` in CI, where the hook repositories can be asked |
| Each scanner has its own mode | `bandit-mode`, `semgrep-mode`, `pip-audit-mode` and `ignore-vulns` in `security-scan.yml` | `test_each_scanner_has_its_own_mode_and_semgrep_its_baseline` fails when a scanner stops following its own mode, pip-audit loses `ignore-vulns`, or semgrep its baseline |

**Lock files.** A pin is edited in `requirements.in`; the lock is regenerated in the same commit
with the command on the second line of the `requirements.txt` beside it (run it in that folder):

```bash
uv pip compile requirements.in --universal --generate-hashes --python-version 3.11 -o requirements.txt
```

`--universal` makes one lock valid on Linux, macOS and Windows. `--python-version` is the lowest
Python it installs on: 3.10 for ruff, mypy and the test tools, 3.11 for the scanners and the
signature verifier. Python 3.10 reached end of life in October 2026, and the last releases of two
indirect dependencies that still support it (filelock for pip-audit, dnspython for the verifier)
have known vulnerabilities, so those locks start at 3.11. When the audit reports a pin that
exists only for an old Python, raise that lock's `--python-version` rather than accept it.

Moving a tool is one pull request. Dependabot opens it with the pin and the regenerated lock; the
tests then name what else must move in it:

- ruff: `required-version` in ruff.toml, the `rev` of both `.pre-commit-config.yaml` files, and
  `tests/policy/ruff/expected.txt` if findings change;
- mypy, bandit, semgrep: their `expected.txt` if findings change, and for bandit the `rev` of both
  `.pre-commit-config.yaml` files;
- pytest: the fallback pin in `python-test.yml`.

A `rev` is the full commit SHA of the release tag, with the tag in its `# frozen:` comment.
`pre-commit autoupdate --freeze --repo <hook repository>` writes both, for the latest tag; add
`-c examples/consumer-repo-example/.pre-commit-config.yaml` for the second file. In CI, a test
asks the hook repository whether the SHA is the commit of the tag the comment names.

**Signatures.** `--require-hashes` says the installed files cannot change; `verify-signatures` says
who built them. PyPI stores an attestation for a file uploaded through trusted publishing: a
Sigstore-signed statement of the repository and workflow that built it and of the file's sha256.
The check compares that digest with the locked hash, so no file is downloaded. It covers bandit,
pip-audit, semgrep, pytest and the verifier itself. Ruff, mypy and PyYAML publish no attestation:
`publishers.toml` lists them as unsigned, and the check fails the day they start, so the policy
is tightened then. Bandit's container image is signed too (cosign), but it is published only as
`latest`, rebuilt every week, and is not what CI installs: the attestation of the wheel is the
signature that covers the installed file. By default the check refreshes Sigstore's trust root
first; `offline: "true"` uses the one shipped in the pinned `sigstore` package. When the refresh
fails, the step stops with exit 2 and says that nothing was verified: run the job again.

**Accepted vulnerabilities.** `tooling-audit` passes five IDs in `ignore-vulns`. Semgrep 1.184.0
pins `mcp==1.29.0` and `opentelemetry-api~=1.37.0` itself, so no lock here can move them, and the
affected code (mcp's HTTP server and client, the parsing of an inbound `tracestate` header) does
not run in a `semgrep scan`. Each ID and its reason is in the comment above the list in
`self-test.yml`. Remove an ID when a semgrep release raises the pin: the audit then guards it
again. Nothing else is accepted, and `required-security-scan.yml` accepts nothing as shipped.

The acceptance is the list in `self-test.yml` and nothing else. With Dependabot alerts on
(step 7 below), expect GitHub to raise its own alerts for the same advisories on
`run-semgrep/requirements.txt`: Dependabot cannot update the two packages past semgrep's own
pins. Dismiss those alerts with the same reason (*Vulnerable code is not actually used*), or
they stay open until semgrep raises the pins.

## One-time settings

1. **Merge methods** of this repository: squash only. Rulesets can only narrow what the
   repository settings allow.

   ```bash
   gh repo edit AGENTIC-AI-PDLC-PLATFORM/ci-reusable-workflows-and-composite-actions-repo \
     --enable-squash-merge --enable-merge-commit=false --enable-rebase-merge=false
   ```

2. **Ruleset on `main`**, after the first push (the five checks must have run once, on a PR) and once
   the team in step 3 is ready. One block does both, like the one for the org ruleset below: it
   creates the ruleset when this repository has none named `main`, and replaces its content with
   the file when it has one, so running the block again changes nothing. When the lookup
   returns anything but a ruleset ID or nothing (GitHub's error JSON, for instance), the block
   sends nothing and prints `NOT SENT` with the value it saw. Run it from the root of this
   repository:

   ```bash
   REPO=AGENTIC-AI-PDLC-PLATFORM/ci-reusable-workflows-and-composite-actions-repo
   FILE=folder-for-administrating-this-repo/ruleset-main.json

   # includes_parents=false: this repository's own rulesets only, not the organization's.
   ID=$(gh api --paginate "repos/$REPO/rulesets?includes_parents=false" --jq '.[] | select(.name == "main") | .id')
   if [[ -z $ID ]]; then                  # no ruleset with that name yet: create it
     gh api --method POST "repos/$REPO/rulesets" --input "$FILE"
   elif [[ $ID =~ ^[0-9]+$ ]]; then       # it exists: replace its content with the file
     gh api --method PUT "repos/$REPO/rulesets/$ID" --input "$FILE"
   else
     echo "NOT SENT: check ID='$ID'" >&2
   fi
   ```

   The five required checks are `lint-policy`, `self-lint / python-lint`, `security-policy`,
   `self-scan / security-scan` and `tooling-audit`. If the ruleset already exists with the first
   two, merge the pull request that adds the other three first (they run on it), then run the
   block: it replaces the ruleset with the file.

   - Squash only and linear history: one PR becomes one commit on `main`.
   - Strict status checks: the branch must be up to date, so the tested merge result is what lands.
   - No force push, no deletion: every SHA a caller pinned stays on `main`.
   - No bypass actors: admins take the same path (they can still edit the ruleset itself).

3. **CODEOWNERS** (repository root): every file is owned by `@AGENTIC-AI-PDLC-PLATFORM/coe-platform-lead`.
   Give that team explicit write access to this repository: GitHub requires it of code owners, even
   when the members already have access. Keep no CODEOWNERS file in `.github/` or `docs/`: GitHub
   reads `.github/`, then the root, then `docs/`, and uses the first one it finds.

   Step 2 depends on two more points about that team:

   - **It must be visible**, not secret: GitHub requires a code-owner team to be visible as well as
     to have write access. Its privacy must read `closed`.
   - **It needs at least two members.** The ruleset of step 2 requires a code owner's approval and
     has no bypass actors, and the author of a pull request cannot approve it: a pull request opened
     by the team's only member could never merge.

   ```bash
   # Write access for the team; then its privacy must print "closed" and its members at least two logins.
   gh api --method PUT orgs/AGENTIC-AI-PDLC-PLATFORM/teams/coe-platform-lead/repos/AGENTIC-AI-PDLC-PLATFORM/ci-reusable-workflows-and-composite-actions-repo \
     -f permission=push
   gh api orgs/AGENTIC-AI-PDLC-PLATFORM/teams/coe-platform-lead --jq .privacy
   gh api orgs/AGENTIC-AI-PDLC-PLATFORM/teams/coe-platform-lead/members --jq '.[].login'
   ```

4. **Dependabot access** (private or internal repository): organization settings, Security
   section, Global settings, *Grant Dependabot access to private repositories*: add this repository.

5. **Enforced mode**: in the org ruleset's *Require workflows to pass before merging* rule, add
   `.github/workflows/required-python-lint.yml` of this repository by commit SHA (the workflow
   entry has a `sha` field beside `ref`), not `main`. `$/` in that file resolves against this
   repository at that SHA. Changing the SHA is the deliberate move, done once `self-test` passed.
   `required-security-scan.yml` is enforced the same way, by a ruleset of its own.
   The commands: [Org ruleset (enforced mode)](#org-ruleset-enforced-mode).

6. **Optional hardening**: the setting *Require actions to be pinned to a full-length commit SHA*
   (Settings, Actions, General) makes GitHub refuse any unpinned action at run time. It applies to
   every workflow of the scope you enable it for, so consumer repos that use tag refs for their own
   actions fail until they pin them too. `$/` references are accepted under it.

7. **Dependabot alerts and security updates** for this repository. `.github/dependabot.yml` alone
   gives the weekly update pull requests. With these two settings on, Dependabot also opens a pull
   request as soon as an advisory matches a pin, without waiting for the weekly run:

   ```bash
   REPO=AGENTIC-AI-PDLC-PLATFORM/ci-reusable-workflows-and-composite-actions-repo
   gh api --method PUT repos/$REPO/vulnerability-alerts          # Dependabot alerts and the dependency graph
   gh api --method PUT repos/$REPO/automated-security-fixes      # Dependabot security updates
   gh api repos/$REPO/automated-security-fixes --jq .enabled     # must print true
   ```

## Consumer repos (opt-in mode)

The examples call this repository at `@REPLACE_WITH_FULL_SHA_OF_MAIN`. Replace it with the current
SHA of `main`, and add `.github/dependabot.yml` from `consumer-repo-example`:

```bash
SHA=$(gh api repos/AGENTIC-AI-PDLC-PLATFORM/ci-reusable-workflows-and-composite-actions-repo/commits/main --jq .sha)
perl -pi -e "s/REPLACE_WITH_FULL_SHA_OF_MAIN/$SHA/" .github/workflows/*.yml
```

Keep comments on the line above `uses:`: Dependabot treats a same-line comment as a version label.
The SHA has no tag, so Dependabot moves it to the latest commit of `main`.

The example `dependabot.yml` also has a `pip` entry for the repository's own Python dependencies:
pip-audit reports a vulnerable one, Dependabot opens the pull request that fixes it. Dependabot
alerts and security updates, switched on in the repository's settings, make that pull request
immediate instead of weekly.

`consumer-repo-example/.pre-commit-config.yaml` is optional: the org's ruff and bandit checks
before a commit is created. It is a copy of the policy at the commit it was taken from, so copy it
again when the org CI pin moves to a commit that changed the tools or the lint policy.

## Org ruleset (enforced mode)

The commands for step 5, run with `gh` signed in as an organization owner. Each required
workflow has its own ruleset, named after it: `required-python-lint` and
`required-security-scan`. Set `WORKFLOW` to the one to create or to move, and run the block
once for each: the two are independent, so the scan can start later than lint, or on other
repositories. Set `TARGETS` to the repositories to enforce, or `["~ALL"]`. Their visibility must
fit this repository's: an internal repository serves internal and private repositories, a
private one private repositories only, and public targets need a public one. This repository is
excluded: `self-test` already lints and scans each of its pull requests at that pull request's
commit, and a faulty pinned policy must never block the pull request that fixes it.
`do_not_enforce_on_create` keeps the rule from blocking the creation of repositories and
branches.

The pinned commit also sets the mode. As shipped, `required-python-lint.yml` passes no inputs, so
ruff and mypy enforce from the first pull request. To start with annotations only, merge a pull
request that uncomments its `with:` lines, then pin that commit; switching to enforce later is a
pull request that deletes them, then a move of the SHA.

`required-security-scan.yml` works the same way: as shipped it passes no inputs, so bandit,
semgrep and pip-audit enforce from the first pull request, and a finding stops the merge. Three
points are its own:

- **Bandit has no baseline.** Semgrep reports only what a pull request adds, but bandit reports
  every finding of the repository: a targeted repository with old findings is blocked until
  they are fixed or marked `# nosec`. To let semgrep and pip-audit enforce first, pin a commit
  whose `with:` sets `bandit-mode: report`.
- **A vulnerability is accepted here, not in the repository it blocks.** pip-audit audits every
  dependency on every pull request, so a new advisory blocks a repository's next pull request,
  whatever that pull request changes. Accepting it (no fixed version yet, or the vulnerable
  code is not used) is a pull request to this repository that adds the ID to `ignore-vulns` in
  `required-security-scan.yml`, with the reason in a comment, then a move of the SHA. It holds
  for every targeted repository.
- **Pull requests and merge groups only.** A required workflow never runs on a schedule. The
  weekly full scan (what semgrep's baseline hides, advisories against dependencies nobody
  touched) is the `schedule` of the opt-in `security-scan.yml`. A targeted repository that
  keeps that file removes its `pull_request` and `merge_group` triggers, or every pull request
  is scanned twice.

One block does both: it creates the ruleset when none named after the workflow exists, and
moves its SHA when one does, so the deliberate move is running the block again. It sends nothing
unless the lookups worked, `WORKFLOW` is one of the two names and `TARGETS` is valid JSON. A
failed `gh api` lookup prints GitHub's error JSON on stdout, so the block requires a numeric
repository ID, a 40-character SHA and a ruleset ID that is a number or empty (no ruleset yet),
and otherwise prints `NOT SENT` with the values it saw.

The block needs `jq`. Install it once, on its own: pasted together with the block, sudo's password
prompt or apt's question would read the next pasted lines as their answers.

```bash
sudo apt update && sudo apt install -y jq    # Ubuntu or WSL; on macOS: brew install jq
```

```bash
export ORG=AGENTIC-AI-PDLC-PLATFORM
export CI=ci-reusable-workflows-and-composite-actions-repo
# The required workflow, which is also the name of its ruleset. One run of the block per value.
export WORKFLOW=required-python-lint      # or: required-security-scan

ID=$(gh api --paginate orgs/$ORG/rulesets --jq ".[] | select(.name == \"$WORKFLOW\") | .id")
CI_ID=$(gh api repos/$ORG/$CI --jq .id)
SHA=$(gh api repos/$ORG/$CI/commits/main --jq .sha)

# A list targets only the repositories it names; '["~ALL"]' targets every repository, future ones
# included. "exclude" always wins over "include". If this CI repository is private or internal,
# public repositories can't use its workflows: exclude them next to $ci in the jq body below
# (exclude: [$ci, "public-repo"]), or their pull requests would wait for a workflow that can't run.
# For a move, keep TARGETS as it was: the PUT replaces the ruleset's conditions too.
# TARGETS='["repo-a", "repo-b"]'
TARGETS='["~ALL"]'

if [[ $WORKFLOW =~ ^required-(python-lint|security-scan)$ && $CI_ID =~ ^[0-9]+$ && $SHA =~ ^[0-9a-f]{40}$ ]] && BODY=$(jq -n \
  --argjson targets "$TARGETS" \
  --arg ci "$CI" \
  --argjson ci_id "$CI_ID" \
  --arg sha "$SHA" \
  --arg workflow "$WORKFLOW" \
  '{
    name: $workflow,
    target: "branch",
    enforcement: "active",
    bypass_actors: [],
    conditions: {
      ref_name: { include: ["~DEFAULT_BRANCH"], exclude: [] },
      repository_name: { include: $targets, exclude: [$ci] }
    },
    rules: [{
      type: "workflows",
      parameters: {
        do_not_enforce_on_create: true,
        workflows: [{ repository_id: $ci_id, path: (".github/workflows/" + $workflow + ".yml"), sha: $sha }]
      }
    }]
  }'); then
  if [[ -z $ID ]]; then                  # no ruleset with that name yet: create it
    gh api --method POST "orgs/$ORG/rulesets" --input - <<<"$BODY"
  elif [[ $ID =~ ^[0-9]+$ ]]; then       # it exists: move its SHA
    gh api --method PUT "orgs/$ORG/rulesets/$ID" --input - <<<"$BODY"
  else
    echo "NOT SENT: check ID='$ID'" >&2
  fi
else
  echo "NOT SENT: check WORKFLOW='$WORKFLOW' CI_ID='$CI_ID' SHA='$SHA' TARGETS='$TARGETS'" >&2
fi
```

After each run, check what GitHub stored: the workflow entry must show your SHA. Then open a pull
request in one targeted repository: a run named after the workflow (`required-python-lint`,
`required-security-scan`) must appear in its checks. Pull requests that were already open run it
only after a new commit, a branch update, or a close and reopen.

```bash
ID=$(gh api --paginate orgs/$ORG/rulesets --jq ".[] | select(.name == \"$WORKFLOW\") | .id")
gh api orgs/$ORG/rulesets/$ID --jq '.rules[] | select(.type == "workflows") | .parameters.workflows'
```

## What is still not enforced

- **The entry-point pin in opt-in mode is a convention.** GitHub's SHA-pinning setting checks
  actions, not reusable-workflow calls, so `python-lint.yml@main` still runs. Two ways make it
  binding: enforced mode with the ruleset at a SHA (the org moves every repo at once), or workflow
  dependency lockfiles (public preview, GitHub Enterprise Cloud), which lock even an `@main`
  reference to a reviewed commit per repository. A repo that runs the security scan, opt-in or
  enforced, gets part of it from semgrep: `org.github-actions.action-not-pinned-to-sha` reports
  an `@main` or tag reference that a pull request adds.
- **`ruff-config` and `mypy-config`**: an opt-in repo that passes its own config is not on the org
  policy at all, so rule changes never reach it. Enforced mode passes no inputs and always uses the
  bundled policies.
- **The inputs of `security-scan.yml` are the caller's.** An opt-in repo chooses its own
  `ignore-vulns`, `severity`, `confidence` and scanner modes, `skip` included. Enforced mode
  passes none of them: the modes and the accepted vulnerabilities of every targeted repo are
  the ones in `required-security-scan.yml`.
- **Enforced mode covers pull requests and merge groups.** A required workflow never runs on a
  schedule, so a targeted repo gets a weekly full scan only if it keeps the opt-in file for it.
- **Bandit has no baseline.** Semgrep reports what a pull request adds; bandit reports every
  finding in the scanned path, so a repo with old findings starts it in `bandit-mode: report`.
  In enforced mode that line is in `required-security-scan.yml`, for every targeted repo.
- **pip-audit audits what a package index serves.** `audit.py` reads `uv.lock`, `poetry.lock`,
  `pdm.lock` and `Pipfile.lock` for it, but a dependency locked from git, from a URL or from a
  local folder has no index version to look up: the summary lists it as not audited. A lock in a
  format version `audit.py` does not know is not guessed at: the next dependency file is
  audited instead, with a warning, and with no other dependency file the audit fails.
- **Signatures cover the tools that publish them.** Ruff, mypy and PyYAML do not, and the
  indirect dependencies in the locks are hash-locked and audited but not signature-checked.
- **Pre-commit hooks are a convenience.** A hook can be skipped or never installed; the checks
  that bind are the ones CI runs.
- **The pins here move only in pull requests.** `.github/dependabot.yml` opens them; a pull
  request that moves ruff, mypy, bandit or semgrep passes only once the policy edits that go with
  the new version are in it. The `uses:` test keeps the action pins full SHAs.
