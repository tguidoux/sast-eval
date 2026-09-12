---
name: release
description: 'Cut and publish a new sast-eval release to PyPI. Use this skill whenever the user asks to release, publish, ship, cut, or bump a new version of sast-eval, or says "make a new release", "publish a new version", "ship 0.x.y", or mentions bumping the version and tagging. Handles the full flow: determine the next version, update CHANGELOG, bump version in both files, build, verify, commit, tag, push, and confirm the PyPI publish.'
argument-hint: 'Optional: the version to release (e.g. 0.1.2, 0.2.0). If omitted, infer the next version from CHANGELOG.md or ask.'
user-invocable: true
disable-model-invocation: false
---

# Release a new sast-eval version

This skill cuts and publishes a new release of `sast-eval` to PyPI. The
publishing itself is automated by the `publish.yml` GitHub Actions workflow
(Trusted Publishing via OIDC) — this skill's job is to prepare the release
correctly, push the tag that triggers the workflow, and confirm it landed.

## How releasing works in this repo

The version lives in **two files** that must stay in sync:

- `pyproject.toml` → `version = "0.1.1"`
- `sast_eval/__init__.py` → `__version__ = "0.1.1"`

A release is triggered by **pushing a `v*` tag** (e.g. `v0.1.2`). The tag push
runs `.github/workflows/publish.yml`, which builds the wheel, verifies it, and
publishes to PyPI via Trusted Publishing — no API token is stored in the repo.
The `pypi` GitHub environment has a required reviewer, so the publish job
pauses for approval before uploading.

Published versions on PyPI are **permanent** — you cannot delete or overwrite
one. A broken release is *yanked* (hidden from default `pip install`), not
removed. So the verify step before tagging matters.

## Steps

### 1. Determine the next version

- If the user gave a version (e.g. "release 0.1.2"), use it.
- Otherwise, read `CHANGELOG.md` — if there's an `## [Unreleased]` section or a
  pending set of changes, infer the bump:
  - **patch** (`0.1.1` → `0.1.2`): bug fixes, small additions, no breaking changes.
  - **minor** (`0.1.1` → `0.2.0`): new features, new subcommands, backward-compatible.
  - **major** (`0.1.1` → `1.0.0`): breaking changes to the CLI, task schema, or
    matcher output.
- If unclear, ask the user which bump they want.

Confirm the version with the user before proceeding if it wasn't explicitly
given.

### 2. Make sure the working tree is clean

```bash
git status --short
```

If there are uncommitted changes, tell the user what's dirty and ask whether to
stash, commit, or abort. Releasing from a dirty tree is a recipe for shipping
the wrong code.

### 3. Update CHANGELOG.md

Read the current `CHANGELOG.md` and add a new `## [<version>] - <YYYY-MM-DD>`
section at the top (under the header), dated today. Move entries from the
`[Unreleased]` section if one exists; otherwise draft entries from the commits
since the last tag:

```bash
git --no-pager log --oneline <last-tag>..HEAD
```

Use [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) categories:
`Added`, `Changed`, `Fixed`, `Removed`. Be concrete — each entry should let a
user understand what changed without reading the diff.

Example entry shape:

```markdown
## [0.1.2] - 2026-09-13

### Fixed

- `sast-eval match` now handles SARIF files with no `region` field (regression
  introduced in 0.1.1).
```

### 4. Bump the version in both files

Edit `pyproject.toml` and `sast_eval/__init__.py` to the new version. They must
match exactly. Do not touch `uv.lock` manually — it gets updated by the build.

### 5. Build and verify locally

This is the gate that catches a broken release before it's permanent.

```bash
rm -rf dist/ build/ *.egg-info sast_eval.egg-info
uv build
```

Then verify:

```bash
# metadata is valid
uvx twine check dist/*

# wheel installs and reports the right version
python -m venv /tmp/verify-$$ && /tmp/verify-$$/bin/pip install --quiet dist/*.whl
/tmp/verify-$$/bin/python -c "import sast_eval; print(sast_eval.__version__)"
# package data is present
/tmp/verify-$$/bin/python -c "from importlib.resources import files; assert (files('sast_eval.matching')/'cwe_map.json').is_file(); print('cwe_map.json OK')"
rm -rf /tmp/verify-$$
```

If any of these fail, **stop** — do not tag. Fix the issue and re-verify.

### 6. Commit the version bump

Stage the version files, the CHANGELOG, and `uv.lock` (if it changed):

```bash
git add pyproject.toml sast_eval/__init__.py CHANGELOG.md uv.lock
git commit -m "Release v<version>

<one-line summary of the release>

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

### 7. Tag and push

```bash
git tag -a v<version> -m "v<version>"
git push origin main
git push origin v<version>
```

The tag push triggers the `publish.yml` workflow.

### 8. Watch the workflow and confirm the publish

```bash
gh run list --workflow=publish.yml --limit 1
```

Watch it to completion. If the `pypi` environment has a required reviewer, the
publish job will pause — tell the user to approve it in the GitHub Actions UI,
then re-check.

Once the workflow is green, confirm the version is live on PyPI:

```bash
curl -s https://pypi.org/pypi/sast-eval/json | python3 -c "import sys,json; print(json.load(sys.stdin)['info']['version'])"
```

It should print the version you just released. If it still shows the old
version, the workflow may still be running or failed — check `gh run view`.

### 9. Report

Tell the user:
- The version that was released
- The PyPI URL: `https://pypi.org/project/sast-eval/<version>/`
- The GitHub release tag: `v<version>`
- A one-line summary of what changed (from the CHANGELOG)

## If something goes wrong

- **Build/verify fails locally**: fix it, re-run step 5. Never tag an
  unverified build.
- **Workflow fails after push**: read `gh run view <id> --log-failed`. Common
  causes: missing `pypi` environment, trusted publisher mismatch, PyPI outage.
  Fix and re-tag (delete the bad tag with `git tag -d v<version>` and
  `git push origin :refs/tags/v<version>` before re-pushing).
- **Published version is broken**: you cannot delete it. Yank it:
  `twine upload --repository pypi --yank sast-eval==<version>` (or use the PyPI
  web UI), then cut a fixed release (e.g. `<version>` → `<version+1>`).

## Notes

- Do not run `twine upload` manually — the workflow handles publishing via
  Trusted Publishing. Manual upload would bypass the OIDC chain of trust.
- The `Co-authored-by: Copilot` trailer in the commit message is the repo
  convention; include it unless the user says not to.
- If the user asks to release from a branch other than `main`, stop and ask —
  releases should come from `main`.
