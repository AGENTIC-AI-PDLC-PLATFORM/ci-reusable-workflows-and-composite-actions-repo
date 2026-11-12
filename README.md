# Org-wide Python CI for GitHub Actions

Reusable workflows (org entry points) → composite actions (Python implementations, versioned with their code).
Every internal reference uses `$/`, so a workflow and the actions it calls always come from the same commit.

```
ci-reusable-workflows-and-composite-actions-repo/   → push as AGENTIC-AI-PDLC-PLATFORM/ci-reusable-workflows-and-composite-actions-repo
├── .pre-commit-config.yaml       this repository's own hooks: the ruff and bandit of CI, before the commit
├── CODEOWNERS                    the policy owners review every change
├── ENFORCEMENT.md                how the versioning promise in ruff.toml and mypy.ini is enforced
├── README.md                     this file
├── examples/
│   └── consumer-repo-example/    templates for the opt-in repos: inert here, active once copied to their root
│       ├── .pre-commit-config.yaml   the org's ruff and bandit checks before a commit (optional)
│       └── .github/
│           ├── dependabot.yml        moves the opt-in repo's SHA pin, and its Python dependencies, in reviewed pull requests
│           └── workflows/            lint.yml · test.yml · security-scan.yml (opt-in mode)
├── folder-for-administrating-this-repo/
│   └── ruleset-main.json         ruleset for this repository's main: squash only, required checks
├── tests/                        policy tests, fixtures and their expected findings (self-test.yml)
│   ├── requirements.in           pinned test tools
│   └── requirements.txt          their hash lock, generated
└── .github/
    ├── dependabot.yml                proposes the update of every pin of this repository
    ├── workflows/
    │   ├── python-lint.yml           reusable workflow: ruff + mypy
    │   ├── python-test.yml           reusable workflow: pytest
    │   ├── security-scan.yml         reusable workflow: bandit + semgrep + pip-audit
    │   ├── required-python-lint.yml  enforced mode: the file an org ruleset runs on every targeted repo
    │   ├── required-security-scan.yml  enforced mode: the same, for the security scan
    │   └── self-test.yml             this repository's CI: proves each commit before callers can pin it
    └── actions/
        ├── common/
        │   ├── install-python/        action.yml   actions/setup-python, job PATH untouched by default
        │   └── install-dependencies/  action.yml   private venv + pip install (--require-hashes for locks), outputs its python
        ├── python-lint/
        │   ├── run-ruff/
        │   │   ├── action.yml          composite action: setup + execution
        │   │   ├── lint.py             the Python implementation (replace run_checks())
        │   │   ├── requirements.in     pinned ruff
        │   │   ├── requirements.txt    its hash lock, generated
        │   │   └── ruff.toml           org lint policy
        │   └── run-mypy/
        │       ├── action.yml          composite action: setup + execution
        │       ├── typecheck.py        the Python implementation (same contract as lint.py)
        │       ├── requirements.in     pinned mypy
        │       ├── requirements.txt    its hash lock, generated
        │       └── mypy.ini            org type-check policy
        ├── security-scan/              each folder: action.yml, its script, requirements.in, requirements.txt
        │   ├── run-bandit/
        │   │   └── scan.py             Python code scan at the org thresholds
        │   ├── run-pip-audit/
        │   │   └── audit.py            dependency audit: finds what to audit, lock files included
        │   └── run-semgrep/
        │       ├── rule_scan.py        scan with the org's own rules, baseline on pull requests
        │       └── rules/              python.yml · github-actions.yml · dockerfile.yml
        └── supply-chain/
            └── verify-signatures/      action.yml, requirements.in, requirements.txt
                ├── verify.py           checks the PyPI attestations of the pinned tools
                └── publishers.toml     who must have signed each pinned tool
```

## What `examples/consumer-repo-example/` is

The files an opt-in repository copies from here. In this repository they do nothing: GitHub runs only the
workflows in `.github/workflows/` at the root of a repository, Dependabot reads only the root
`.github/dependabot.yml`, and pre-commit only the root `.pre-commit-config.yaml`. Copied to the same paths at
the root of an opt-in repo, they act there:

| File, at the opt-in repo's root | What it does there |
|---|---|
| `.github/workflows/lint.yml` | Calls `python-lint.yml` (ruff + mypy) on every pull request and merge group |
| `.github/workflows/test.yml` | Calls `python-test.yml` (pytest) on the same events |
| `.github/workflows/security-scan.yml` | Calls `security-scan.yml` (bandit + semgrep + pip-audit) on the same events, and once a week: new advisories appear without any code change |
| `.github/dependabot.yml` | Opens the pull requests that move the pin of the three workflows to the latest commit of this repository's `main` (one pull request for the three), and those that update the repo's own Python dependencies |
| `.pre-commit-config.yaml` | Optional: the org's ruff and bandit checks on the developer's machine, before a commit exists |

*Opt-in mode*: the repo chooses these files, and its admins can remove them. In enforced mode an org ruleset
runs lint and the security scan with no file in the repo (*Adoption*, below); `test.yml`, `dependabot.yml`
and the weekly run of `security-scan.yml` still come from here.

To copy them, from the root of the opt-in repo, with an up-to-date clone of this repository next to it:

```bash
EX=../ci-reusable-workflows-and-composite-actions-repo/examples/consumer-repo-example
mkdir -p .github/workflows
# Remove from the list the files the repo does not want. A file the repo already has is kept, not replaced.
for f in .github/workflows/lint.yml .github/workflows/test.yml .github/workflows/security-scan.yml \
         .github/dependabot.yml .pre-commit-config.yaml; do
  if [ -e "$f" ]; then echo "kept your $f: merge $EX/$f into it by hand"; else cp "$EX/$f" "$f"; fi
done
```

Running it again changes nothing. Then replace `REPLACE_WITH_FULL_SHA_OF_MAIN` (*Setup*, step 6) and check
the inputs the workflows set: `path: src` (lint, security scan) assumes the code is in `src/`, and
`requirements: requirements.txt` (test) assumes that file exists. Delete a line to get its default.

`tests/test_supply_chain.py` keeps one template in step with CI: it fails when the example
`.pre-commit-config.yaml` pins another ruff or bandit than CI does, or runs them with other arguments.

## What `run-mypy` does

Ruff checks how the code is written (style, unused imports, likely bugs, import order). It does not check types.
`run-mypy` runs **mypy**, a static type checker: it reads type hints and inferred types and reports code that
would break at runtime (wrong argument types, `None` used where a value is required, missing attributes,
wrong return types) before any test runs.

- Same contract as `run-ruff`: annotations on the PR diff, a job-summary table, the `issues` output,
  `enforce` / `report` modes.
- Unlike ruff, mypy must see third-party packages to check calls into them: pass `mypy-requirements`.
  Without it, the org policy (`ignore_missing_imports`) treats untyped imports as `Any`.
- Syntax errors and "duplicate module" errors are reported as findings. A path with no Python file passes, as with ruff.
- mypy derives module names from the folder layout. If it reports *Duplicate module* or *found twice under
  different module names* (folders without `__init__.py`, e.g. tests importing `src.x`), give that repo its own
  config through `mypy-config` with `explicit_package_bases = True`. The org policy leaves it off on purpose:
  in a src layout it would silently stop checking imports between the package's own modules.

## What `security-scan.yml` does

Three scanners, each a composite action with its own private venv, its own pin and its own mode:

| Scanner | What it reads | What it reports |
|---|---|---|
| `run-bandit` | Python code, one call at a time | Dangerous calls at the org thresholds (severity and confidence `medium`): `shell=True`, `yaml.load`, `torch.load`, Hugging Face downloads not pinned to a commit, and so on |
| `run-semgrep` | Python, workflows and Dockerfiles, with the org's own rules (`rules/`) | What bandit cannot: a value followed from where it enters the program to where it is used, rules the org wrote itself, and code that is not Python |
| `run-pip-audit` | Dependencies | Known vulnerabilities in the pinned or declared versions |

- Same contract as `run-ruff`: annotations on the PR diff, a job-summary table, the `issues` output,
  `enforce` / `report` modes.
- **One mode per scanner.** `mode` sets all three. `bandit-mode`, `semgrep-mode` and `pip-audit-mode` set one
  scanner (`enforce`, `report` or `skip`) while the others keep following `mode`: a dependency problem can stop
  blocking without switching the code scans off.
- **Accepted vulnerabilities.** `ignore-vulns` lists the IDs (PYSEC, GHSA or CVE) pip-audit must not report: a
  vulnerability with no fixed version yet, or one that does not apply to how the package is used. pip-audit
  runs with `--ignore-vuln` for each, and the job summary keeps listing them.
- **pip-audit finds its input.** Without `requirements`, it audits what it finds in `project-path` (default: the
  repository root): `pylock.toml`, else the lock file of uv, Poetry, PDM or Pipenv (`uv.lock`, `poetry.lock`,
  `pdm.lock`, `Pipfile.lock`), else `requirements*.txt`, else `pyproject.toml` (the declared ranges, resolved by
  pip-audit). `requirements` replaces the search, and takes lock files too.
- **A lock file is audited exactly as written**, like a requirements file in which every line carries a hash:
  every version it holds, whatever its environment marker or dependency group, and nothing is installed.
  pip-audit cannot read the four lock formats itself, so `audit.py` reads them. What a lock takes from git or
  from a URL has no index version to look up: the summary lists it as not audited. A lock in a format version
  `audit.py` does not know is not guessed at: the next dependency file is audited, and a warning says so. With
  no other dependency file the audit fails: a lock that cannot be read is not a project without dependencies.
- **Semgrep blocks what a pull request adds.** On `pull_request` and `merge_group` it compares with the base
  commit and reports only the findings that are not already there. Every other event (the weekly `schedule`)
  reports everything. Bandit has no baseline: phase it in with `bandit-mode: report`.
- Semgrep's rules are local files, and it runs with metrics and its version check off: nothing leaves the runner.
  It skips what git ignores and, unless the repository has its own `.semgrepignore`, its default list (`tests/`,
  `node_modules/`, …).
- The scanners need Python 3.11 or newer (`python-version`, default 3.12).

The rules shipped in `run-semgrep/rules/`:

| Rule | Reports |
|---|---|
| `org.python.tainted-command-execution` | Untrusted input (keyboard, command line, HTTP request, the arguments of a function exposed to a language model as a tool) reaching a shell or `eval` / `exec` |
| `org.python.tainted-sql-query` | The same input built into the text of a SQL statement |
| `org.python.dangerous-deserialization-flag` | `allow_dangerous_deserialization=True` |
| `org.github-actions.untrusted-expression-in-run` | `${{ github.event… }}`, `${{ github.head_ref }}` or `${{ inputs… }}` expanded inside a `run:` script |
| `org.github-actions.action-not-pinned-to-sha` | An action, reusable workflow or container image referenced by a tag or branch |
| `org.dockerfile.base-image-not-pinned` | `FROM` an image with no tag or with `latest` |

A new rule is a file or an entry under `rules/`, a case in `tests/policy/semgrep/` and its line in `expected.txt`,
in one commit: `test_every_semgrep_rule_has_a_case_in_the_fixtures` fails otherwise.

Moving an existing caller to this commit changes three things: pip-audit now runs even without `requirements`;
semgrep runs (`semgrep-mode: report` or `skip` phases it in); the checkout fetches one more commit on pull
requests, and the full history in a merge queue.

## Pins, lock files and signatures

Each tool is pinned in a `requirements.in`, the line a person edits, and installed from the `requirements.txt`
generated beside it: every package, indirect ones included, with its sha256 hashes, for Linux, macOS and
Windows. `install-dependencies` installs these files with `pip --require-hashes`, so nothing but the files
hashed there can be installed. To regenerate a lock after editing its pin:

```bash
cd .github/actions/security-scan/run-bandit      # any folder that has a requirements.in
uv pip compile requirements.in --universal --generate-hashes --python-version 3.11 -o requirements.txt
```

The exact command is the second line of each `requirements.txt`. Its `--python-version` is the lowest Python
the lock installs on: 3.10 for ruff, mypy and the test tools, 3.11 for the scanners and the signature verifier.

The `tooling-audit` job of `self-test.yml` checks all the locks on every pull request and every week:

- **pip-audit** audits every pin. A known vulnerability fails the job, unless its ID is in the job's
  `ignore-vulns` list, where a comment says why it is accepted.
- **`verify-signatures`** checks where the files of the pinned tools came from. PyPI keeps a Sigstore
  attestation next to a file uploaded through trusted publishing; `publishers.toml` names the repository that
  must have signed each tool (bandit, pip-audit, semgrep, pytest, the verifier itself), and lists the tools
  whose upstream signs nothing (ruff, mypy, PyYAML), which rest on their hashes alone.

`.github/dependabot.yml` proposes the update of every pin: the locks (it regenerates the hashes) and the
third-party actions. `ENFORCEMENT.md` has the one-time settings and what each check guarantees.

## Pre-commit hooks

`.pre-commit-config.yaml` (this repository) and `examples/consumer-repo-example/.pre-commit-config.yaml` (for
opt-in repos) run ruff and bandit before a commit is created:

```bash
pip install pre-commit && pre-commit install
```

They are the tools of CI: the same versions (each `rev` is the full commit SHA of that release), the org lint
policy, and bandit's `-ll -ii`, which is severity and confidence `medium`, the defaults of `security-scan.yml`.
`tests/test_supply_chain.py` fails when a hook and a CI pin differ. The hooks only report: they
rewrite no file and, with ruff's `--no-cache` as in CI, leave no cache folder in the repository.
A hook can be skipped with `git commit --no-verify`; CI cannot: the hooks are the fast feedback,
CI stays the gate.

## Setup

1. The organization is `AGENTIC-AI-PDLC-PLATFORM`: the consumer examples and every command here already name
   it, and `CODEOWNERS`, at the repository root, names the policy owners. No workflow or action contains the
   org name: every internal reference is `$/`.
2. Create `AGENTIC-AI-PDLC-PLATFORM/ci-reusable-workflows-and-composite-actions-repo` from the
   `ci-reusable-workflows-and-composite-actions-repo/` folder (private or internal is fine).
3. In that repository: **Settings > Actions > General > Access**, choose
   *Accessible from repositories in the 'AGENTIC-AI-PDLC-PLATFORM' organization*.
   No PAT is needed. Actions and reusable workflows in a private repo cannot be used by public repos.
4. Push to `main`. There is no release step and nothing to tag.
5. Apply the one-time settings in `ENFORCEMENT.md` (merge methods, ruleset, Dependabot access and alerts).
6. In each opt-in repo, copy the templates (*What `examples/consumer-repo-example/` is*, above), then replace
   `REPLACE_WITH_FULL_SHA_OF_MAIN` with the current SHA of `main`:

   ```bash
   SHA=$(gh api repos/AGENTIC-AI-PDLC-PLATFORM/ci-reusable-workflows-and-composite-actions-repo/commits/main --jq .sha)
   perl -pi -e "s/REPLACE_WITH_FULL_SHA_OF_MAIN/$SHA/" .github/workflows/*.yml
   ```

`$/` needs github.com (it is not available on GitHub Enterprise Server) and Actions runner **2.336.0 or newer**.
GitHub-hosted runners qualify. Update self-hosted runners first: older runners reject `$/` references.

## Adoption: pick one

| Mode | What you do | Result |
|---|---|---|
| Opt-in | Each repo adds the files it wants from `examples/consumer-repo-example/.github/workflows/` | Status checks `lint / python-lint`, `test / python-test`, `security / security-scan`; make them required per repo if needed |
| Enforced | An org ruleset: *Require workflows to pass before merging* → this repository @ a full commit SHA of `main` → `.github/workflows/required-python-lint.yml`; a second ruleset does the same with `required-security-scan.yml` | Runs on PRs of every targeted repo, no file in them, cannot be removed by repo admins. A failed run stops the merge |

`required-python-lint.yml` calls `python-lint.yml` with no inputs, so every targeted repo runs the org
policies exactly as shipped. Moving the ruleset to a newer SHA is the deliberate step.

Phased rollout: call with `mode: report` first (annotations only), then switch to `enforce`.
Type checking can follow later: `mypy-mode: report` (or `skip`) while ruff is already enforced.
`required-python-lint.yml` carries both lines, commented out.

`required-security-scan.yml` is the same for `security-scan.yml`: with no inputs, bandit, semgrep and pip-audit
run on every pull request of a targeted repo, and a finding stops the merge. Three things differ from lint:

- **Rollout.** `mode: report` first, or one scanner at a time. Semgrep reports only what a pull request adds,
  but bandit has no baseline: a repo with old bandit findings is blocked until they are fixed or marked
  `# nosec`. `bandit-mode: report` lets semgrep and pip-audit enforce first. The file carries these lines,
  commented out.
- **Accepted vulnerabilities.** pip-audit audits every dependency on every pull request, so a new advisory
  blocks a repo's next pull request, whatever that pull request changes. The repo cannot accept it by itself:
  the ID goes into `ignore-vulns` of `required-security-scan.yml`, with its reason in a comment, by a pull
  request here, and holds for every targeted repo.
- **No weekly run.** A required workflow runs on pull requests and merge groups only. The weekly full scan is
  the `schedule` of the opt-in `security-scan.yml`: a targeted repo that keeps that file removes its
  `pull_request` and `merge_group` triggers, or every pull request is scanned twice.

## Versioning: `$/` instead of tags

- Inside this repository, workflows and actions reference each other as `$/.github/...`: this repository
  **at the exact commit being run**, with no checkout and no `@ref`. It works for workflow steps, composite
  action steps (nested composition) and reusable workflow calls.
- Callers choose one ref, on the entry point only: a full 40-character commit SHA of `main`. Dependabot
  proposes each move as a pull request in which the new policy runs. `@main` also resolves, but then every
  push here changes every caller's checks at once.

  Whatever they choose, every `$/` below it resolves to that same SHA. A workflow can never run against
  actions from another commit, and the third-party actions underneath are pinned to full SHAs too.
- `./.github/actions/...` would resolve inside the caller's checkout. `AGENTIC-AI-PDLC-PLATFORM/...@v1` would bring back the
  tag-and-move release process, and callers pinned to a SHA would still get whatever `v1` points to.
- `$/` means "this repository" only inside this repository. Consumer repos keep the full form
  `AGENTIC-AI-PDLC-PLATFORM/ci-reusable-workflows-and-composite-actions-repo/.github/workflows/<file>@<ref>`.
- Tooling: actionlint 1.7.12 does not recognize `$/` yet. Until it does:
  `actionlint -ignore 'specifying action "\$/' -ignore 'reusable workflow call "\$/'`

## Test locally

From the repository root:

```bash
R=.github/actions/python-lint
pip install -r $R/run-ruff/requirements.txt -r $R/run-mypy/requirements.txt
python $R/run-ruff/lint.py      --path . --config $R/run-ruff/ruff.toml --mode report
python $R/run-mypy/typecheck.py --path . --config $R/run-mypy/mypy.ini  --mode report
# The policy tests that self-test.yml's lint-policy job runs on every pull request.
# -B and -p no:cacheprovider, as in CI: the run leaves no __pycache__ or .pytest_cache here.
pip install -r tests/requirements.txt
python -B -m pytest -p no:cacheprovider tests --ignore tests/test_security_policy.py
# The scanner tests of its security-policy job: one venv per scanner, as in CI
# (semgrep pins dependencies at versions the other tools do not share). One folder, rebuilt by
# each run (--clear): the venvs are exactly the lock files, and runs do not pile up.
S=.github/actions/security-scan; V=${TMPDIR:-/tmp}/org-ci-scanner-venvs
for tool in bandit pip-audit semgrep; do
  python -m venv --clear $V/$tool && $V/$tool/bin/pip install --require-hashes -r $S/run-$tool/requirements.txt
done
ORG_CI_BANDIT_PYTHON=$V/bandit/bin/python ORG_CI_PIP_AUDIT_PYTHON=$V/pip-audit/bin/python \
ORG_CI_SEMGREP_PYTHON=$V/semgrep/bin/python ORG_CI_ONLINE=1 \
python -B -m pytest -p no:cacheprovider tests/test_security_policy.py
```

The block can be run again as it is: every command ends in the same state, and nothing is written
into the repository.

`ORG_CI_ONLINE=1` also runs the tests that need the network: pip-audit's advisory lookups and, in
`tests/test_supply_chain.py`, the check that each pre-commit `rev` is the commit of the tag it names.
