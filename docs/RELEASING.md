# Releasing `sast-eval`

Checklist for publishing a new version to PyPI. Publishing is gated behind a
pushed `v*` tag and uses **Trusted Publishing** (OIDC) — no API token is stored
in the repo.

## One-time setup (do this before the first release)

### PyPI

1. **Reserve / create the project.** Either:
   - Publish the first version manually with `twine upload` (creates the
     project under your account), or
   - Reserve the name at <https://pypi.org/manage/projects/>.
2. **Add a Trusted Publisher** at
   <https://pypi.org/manage/project/sast-eval/settings/publishing/>:
   - Owner: your GitHub username
   - Repository: `sast-eval`
   - Workflow filename: `publish.yml`
   - Environment name: `pypi`
3. **Confirm you are the sole Owner** on the project's Collaboration page
   (<https://pypi.org/manage/project/sast-eval/collaboration/>). Remove any
   other owners/uploaders. Only PyPI owners can publish or delegate publishing.

### GitHub

4. **Enable 2FA** on your GitHub account (Settings → Password and authentication).
5. **Restrict who can push to `main`**: Settings → Branches → branch protection
   rule for `main` → require your review / restrict direct pushes.
6. **No collaborators**: Settings → Collaborators and teams should be empty (or
   only people you fully trust). Only collaborators with write access can push
   a tag, and only a tag can trigger the publish workflow.
7. **Tag protection** (optional): Settings → Tags → add a protection rule for
   `v*` restricting creation to admins.

## Every release

The version is stored in two places — keep them in sync:

- [`pyproject.toml`](../pyproject.toml) → `version = "0.1.0"`
- [`sast_eval/__init__.py`](../sast_eval/__init__.py) → `__version__ = "0.1.0"`

```bash
# 1. Bump the version in both files (e.g. 0.1.0 → 0.2.0)
$EDITOR pyproject.toml sast_eval/__init__.py

# 2. Verify locally
rm -rf dist/ build/ *.egg-info sast_eval.egg-info
uv build                              # or: python -m build
twine check dist/*
python -m venv /tmp/verify && /tmp/verify/bin/pip install dist/*.whl
/tmp/verify/bin/python -c "import sast_eval; print(sast_eval.__version__)"
/tmp/verify/bin/python -c "from importlib.resources import files; assert (files('sast_eval.matching')/'cwe_map.json').is_file()"

# 3. Commit the version bump
git add pyproject.toml sast_eval/__init__.py
git commit -m "Bump version to 0.2.0"

# 4. Tag the release (this is what triggers the publish workflow)
git tag -a v0.2.0 -m "v0.2.0"
git push origin main --tags

# 5. Watch the workflow
#    https://github.com/<you>/sast-eval/actions
#    The "publish" workflow builds, verifies, and uploads to PyPI.

# 6. Confirm the release is live
#    https://pypi.org/project/sast-eval/#history
```

## Rollback (if a release is broken or compromised)

You **cannot** delete or overwrite a published version on PyPI — once a version
number is uploaded, it's permanent. To recover from a bad release:

1. **Yank** the broken version (hides it from default `pip install` but keeps it
   available for pinned installs):
   ```bash
   pip install twine
   twine upload --repository pypi --yank sast-eval==0.2.0
   ```
   Or yank from the web UI: <https://pypi.org/manage/project/sast-eval/releases/>.
2. **Bump and release a fixed version** (e.g. `0.2.1`).
3. If a release was compromised (malicious upload), contact
   <security@pypi.org> immediately and rotate your GitHub account credentials.

## Why this is safe

- **No long-lived PyPI token** in the repo or GitHub secrets. Trusted
  Publishing uses short-lived OIDC tokens issued per-workflow-run.
- **Only a `v*` tag** triggers the workflow — branch pushes and PRs cannot.
- **Only you can push a tag** (GitHub write access, behind 2FA + branch
  protection).
- **Only you are a PyPI Owner** (can delegate or revoke publishing).
- Every publish is visible in the PyPI release history and the GitHub Actions
  log, so a malicious release is immediately detectable and yankable.
