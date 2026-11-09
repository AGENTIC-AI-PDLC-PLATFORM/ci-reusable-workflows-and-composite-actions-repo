# How the versioning promise is enforced

ruff.toml and mypy.ini open with the same sentence:

> Versioned together with lint.py (typecheck.py) and action.yml: a rule change ships in the same
> commit as the code; repos pinned to a SHA move deliberately.

| Clause | Enforced by | Fails loudly when |
|---|---|---|
| Versioned together with the script and action.yml | `$/` for every internal `uses:`, `$GITHUB_ACTION_PATH` for the scripts, policies and requirements: the caller's single ref selects all of them | By construction. `test_every_uses_is_this_commit_or_a_full_sha` fails on a `./` or by-name self-reference that would break it |
| … including ruff itself | `required-version` in ruff.toml, equal to the pin in run-ruff/requirements.txt | Ruff exits 2 under any other version. `test_ruff_pin_and_required_version_agree` fails when the two pins differ |
| … including mypy itself | mypy has no `required-version` setting, so a test plays that role | `test_mypy_pin_is_the_mypy_that_runs` fails when the installed mypy is not the pin in run-mypy/requirements.txt |
| … and every third-party action underneath | Full 40-character commit SHAs | The same `uses:` test fails on any tag or branch ref |
| A rule change ships in the same commit as the code | `main` takes only squash merges of PRs approved by code owners, whose `lint-policy` and `self-lint` checks passed on an up-to-date branch | `test_ruff_findings_match_expected` and `test_mypy_findings_match_expected` fail when findings change without `tests/policy/<tool>/expected.txt`. `self-lint` fails when this repo's own code breaks a new rule. The fixture steps fail when an action stops reporting what its policy finds |
| Repos pinned to a SHA move deliberately | Opt-in repos pin a full SHA and Dependabot proposes each move as a PR that runs the new policy. Enforced mode pins the org ruleset to a SHA | See [What is still not enforced](#what-is-still-not-enforced) |

Squash-only is what makes "same commit" literal. With merge or rebase merges, every commit of a
multi-commit PR lands on `main`, including one where a policy changed and its script did not
yet. A caller, Dependabot or the org ruleset could pin that commit.

The fixtures cover every selected ruff family except E9 (a syntax error would stop ruff parsing
the rest), and both mypy.ini settings: dropping `check_untyped_defs` removes a finding, dropping
`ignore_missing_imports` adds one.

Third-party actions are pinned to what `@v7` resolved to on 2026-11-03:
`actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1` (v7.0.1) and
`actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0` (v7.1.0).

## One-time settings

1. **Merge methods** of this repository: squash only. Rulesets can only narrow what the
   repository settings allow.

   ```bash
   gh repo edit AGENTIC-AI-PDLC-PLATFORM/ci-reusable-workflows-and-composite-actions-repo \
     --enable-squash-merge --enable-merge-commit=false --enable-rebase-merge=false
   ```

2. **Ruleset on `main`**, after the first push (the two checks must have run once, on a PR) and once
   the team in step 3 is ready:

   ```bash
   gh api --method POST repos/AGENTIC-AI-PDLC-PLATFORM/ci-reusable-workflows-and-composite-actions-repo/rulesets \
     --input folder-for-administrating-this-repo/ruleset-main.json
   ```

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
   The commands: [Org ruleset (enforced mode)](#org-ruleset-enforced-mode).

6. **Optional hardening**: the setting *Require actions to be pinned to a full-length commit SHA*
   (Settings, Actions, General) makes GitHub refuse any unpinned action at run time. It applies to
   every workflow of the scope you enable it for, so consumer repos that use tag refs for their own
   actions fail until they pin them too. `$/` references are accepted under it.

## Consumer repos (opt-in mode)

The examples call this repository at `@REPLACE_WITH_FULL_SHA_OF_MAIN`. Replace it with the current
SHA of `main`, and add `.github/dependabot.yml` from `consumer-repo-example`:

```bash
SHA=$(gh api repos/AGENTIC-AI-PDLC-PLATFORM/ci-reusable-workflows-and-composite-actions-repo/commits/main --jq .sha)
perl -pi -e "s/REPLACE_WITH_FULL_SHA_OF_MAIN/$SHA/" .github/workflows/*.yml
```

Keep comments on the line above `uses:`: Dependabot treats a same-line comment as a version label.
The SHA has no tag, so Dependabot moves it to the latest commit of `main`.

## Org ruleset (enforced mode)

The commands for step 5, run with `gh` signed in as an organization owner. Set `TARGETS` to the
repositories to enforce, or `["~ALL"]`. Their visibility must fit this repository's: an internal
repository serves internal and private repositories, a private one private repositories only, and
public targets need a public one. This repository is excluded: `self-test` already lints each of
its pull requests at that pull request's commit, and a faulty pinned policy must never block the
pull request that fixes it. `do_not_enforce_on_create` keeps the rule from blocking the creation of
repositories and branches.

The pinned commit also sets the mode. As shipped, `required-python-lint.yml` passes no inputs, so
ruff and mypy enforce from the first pull request. To start with annotations only, merge a pull
request that uncomments its `with:` lines, then pin that commit; switching to enforce later is a
pull request that deletes them, then a move of the SHA.

One block does both: it creates the ruleset when none named `required-python-lint` exists, and
moves its SHA when one does, so the deliberate move is running the block again. It sends nothing
unless the lookups worked and `TARGETS` is valid JSON. A failed `gh api` lookup prints GitHub's
error JSON on stdout, so the block requires a numeric repository ID, a 40-character SHA and a
ruleset ID that is a number or empty (no ruleset yet), and otherwise prints `NOT SENT` with the
values it saw.

The block needs `jq`. Install it once, on its own: pasted together with the block, sudo's password
prompt or apt's question would read the next pasted lines as their answers.

```bash
sudo apt update && sudo apt install -y jq    # Ubuntu or WSL; on macOS: brew install jq
```

```bash
export ORG=AGENTIC-AI-PDLC-PLATFORM
export CI=ci-reusable-workflows-and-composite-actions-repo

ID=$(gh api --paginate orgs/$ORG/rulesets --jq '.[] | select(.name == "required-python-lint") | .id')
CI_ID=$(gh api repos/$ORG/$CI --jq .id)
SHA=$(gh api repos/$ORG/$CI/commits/main --jq .sha)

# A list targets only the repositories it names; '["~ALL"]' targets every repository, future ones
# included. "exclude" always wins over "include". If this CI repository is private or internal,
# public repositories can't use its workflows: exclude them next to $ci in the jq body below
# (exclude: [$ci, "public-repo"]), or their pull requests would wait for a workflow that can't run.
# For a move, keep TARGETS as it was: the PUT replaces the ruleset's conditions too.
# TARGETS='["repo-a", "repo-b"]'
TARGETS='["~ALL"]'

if [[ $CI_ID =~ ^[0-9]+$ && $SHA =~ ^[0-9a-f]{40}$ ]] && BODY=$(jq -n \
  --argjson targets "$TARGETS" \
  --arg ci "$CI" \
  --argjson ci_id "$CI_ID" \
  --arg sha "$SHA" \
  '{
    name: "required-python-lint",
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
        workflows: [{ repository_id: $ci_id, path: ".github/workflows/required-python-lint.yml", sha: $sha }]
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
  echo "NOT SENT: check CI_ID='$CI_ID' SHA='$SHA' TARGETS='$TARGETS'" >&2
fi
```

After each run, check what GitHub stored: the workflow entry must show your SHA. Then open a pull
request in one targeted repository: a `required-python-lint` run must appear in its checks. Pull
requests that were already open run it only after a new commit, a branch update, or a close and
reopen.

```bash
ID=$(gh api --paginate orgs/$ORG/rulesets --jq '.[] | select(.name == "required-python-lint") | .id')
gh api orgs/$ORG/rulesets/$ID --jq '.rules[] | select(.type == "workflows") | .parameters.workflows'
```

## What is still not enforced

- **The entry-point pin in opt-in mode is a convention.** GitHub's SHA-pinning setting checks
  actions, not reusable-workflow calls, so `python-lint.yml@main` still runs. Two ways make it
  binding: enforced mode with the ruleset at a SHA (the org moves every repo at once), or workflow
  dependency lockfiles (public preview, GitHub Enterprise Cloud), which lock even an `@main`
  reference to a reviewed commit per repository.
- **`ruff-config` and `mypy-config`**: an opt-in repo that passes its own config is not on the org
  policy at all, so rule changes never reach it. Enforced mode passes no inputs and always uses the
  bundled policies.
- **The third-party pins here do not move by themselves.** Bump them in a pull request; the
  `uses:` test keeps them full SHAs.
