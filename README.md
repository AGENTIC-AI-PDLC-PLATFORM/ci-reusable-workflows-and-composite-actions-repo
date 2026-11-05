# Org-wide Python CI for GitHub Actions

Reusable workflows (org entry points) → composite actions (Python implementations, versioned with their code).
Every internal reference uses `$/`, so a workflow and the actions it calls always come from the same commit.

```
ci-reusable-workflows-and-composite-actions-repo/   → push as AGENTIC-AI-PDLC-PLATFORM/ci-reusable-workflows-and-composite-actions-repo
├── CODEOWNERS                    the policy owners review every change
├── ENFORCEMENT.md                how the versioning promise in ruff.toml and mypy.ini is enforced
├── README.md                     this file
├── folder-for-administrating-this-repo/
│   └── ruleset-main.json         ruleset for this repository's main: squash only, required checks
├── tests/                        policy tests, fixtures and their expected findings (self-test.yml)
└── .github/
    ├── workflows/
    │   ├── python-lint.yml           reusable workflow: ruff + mypy
    │   ├── python-test.yml           reusable workflow: pytest
    │   ├── security-scan.yml         reusable workflow: bandit + pip-audit
    │   ├── required-python-lint.yml  enforced mode: the file an org ruleset runs on every targeted repo
    │   └── self-test.yml             this repository's CI: proves each commit before callers can pin it
    └── actions/
        ├── common/
        │   ├── install-python/        action.yml   actions/setup-python, job PATH untouched by default
        │   └── install-dependencies/  action.yml   private venv + pip install, outputs its python
        └── python-lint/
            ├── run-ruff/
            │   ├── action.yml          composite action: setup + execution
            │   ├── lint.py             the Python implementation (replace run_checks())
            │   ├── requirements.txt    pinned ruff
            │   └── ruff.toml           org lint policy
            └── run-mypy/
                ├── action.yml          composite action: setup + execution
                ├── typecheck.py        the Python implementation (same contract as lint.py)
                ├── requirements.txt    pinned mypy
                └── mypy.ini            org type-check policy

Not in this repository: next to its folder in org-lint-scaffold.zip, copied into each opt-in repo
consumer-repo-example/.github/workflows/   lint.yml · test.yml · security-scan.yml (opt-in mode)
consumer-repo-example/.github/dependabot.yml   moves the opt-in repo's SHA pin in reviewed pull requests
```

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
5. Apply the one-time settings in `ENFORCEMENT.md` (merge methods, ruleset, Dependabot access).
6. In each opt-in repo, replace `REPLACE_WITH_FULL_SHA_OF_MAIN` with the current SHA of `main`:

   ```bash
   SHA=$(gh api repos/AGENTIC-AI-PDLC-PLATFORM/ci-reusable-workflows-and-composite-actions-repo/commits/main --jq .sha)
   perl -pi -e "s/REPLACE_WITH_FULL_SHA_OF_MAIN/$SHA/" .github/workflows/*.yml
   ```

`$/` needs github.com (it is not available on GitHub Enterprise Server) and Actions runner **2.336.0 or newer**.
GitHub-hosted runners qualify. Update self-hosted runners first: older runners reject `$/` references.

## Adoption: pick one

| Mode | What you do | Result |
|---|---|---|
| Opt-in | Each repo adds the files it wants from `consumer-repo-example/.github/workflows/` | Status checks `lint / python-lint`, `test / python-test`, `security / security-scan`; make them required per repo if needed |
| Enforced | An org ruleset: *Require workflows to pass before merging* → this repository @ a full commit SHA of `main` → `.github/workflows/required-python-lint.yml` | Runs on PRs of every targeted repo, no file in them, cannot be removed by repo admins |

`required-python-lint.yml` calls `python-lint.yml` with no inputs, so every targeted repo runs the org
policies exactly as shipped. Moving the ruleset to a newer SHA is the deliberate step.

Phased rollout: call with `mode: report` first (annotations only), then switch to `enforce`.
Type checking can follow later: `mypy-mode: report` (or `skip`) while ruff is already enforced.
`required-python-lint.yml` carries both lines, commented out.

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
# The policy tests that self-test.yml runs on every pull request:
pip install -r tests/requirements.txt
python -m pytest tests
```
