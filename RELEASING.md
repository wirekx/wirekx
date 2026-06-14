# Releasing

wirekx publishes to PyPI with GitHub Actions Trusted Publishing, using OIDC.
Do not create or store PyPI API tokens for the publish workflow.

## Local Pre-Release Checks

From the repository root:

```bash
python -m pip install build twine
python -m pytest
python -m build
python -m twine check dist/*
unzip -l dist/*.whl | grep wirekx
```

The build must produce both:

```text
dist/wirekx-X.Y.Z-py3-none-any.whl
dist/wirekx-X.Y.Z.tar.gz
```

Do not commit `dist/`, `build/`, or `*.egg-info/` artifacts.

## Release Trigger

Publishing is triggered when a GitHub Release is published.

The release workflow is:

1. The `build` job checks out the repository, installs `build`, and runs
   `python -m build`.
2. The `build` job uploads the `dist/` artifacts.
3. The `publish` job downloads those artifacts.
4. The `publish` job uses PyPI Trusted Publishing through OIDC with
   `pypa/gh-action-pypi-publish@release/v1`.

The publish job uses the GitHub Environment named `pypi`, which should require
manual approval before publishing.

## Hardening Note

The workflow currently uses:

```yaml
pypa/gh-action-pypi-publish@release/v1
```

For stronger supply-chain hardening, consider pinning this action to a full
commit SHA after reviewing the action version you want to trust.

## Manual Steps

Do these by hand. Do not automate them in this repository.

1. pypi.org -> Publishing -> Trusted Publishers -> Add: GitHub Actions, owner
   `wirekx`, repo `wirekx`, workflow `publish.yml`, environment `pypi`.
2. Repeat on test.pypi.org as a dry run. Hardening: consider pinning
   `pypa/gh-action-pypi-publish` to a full commit SHA instead of `@release/v1`.
3. GitHub repo Settings -> Environments -> create `pypi`, add yourself as a
   required reviewer for manual approval on every run.
4. Release: bump version, commit, tag `vX.Y.Z`, create a GitHub Release. This
   triggers the workflow.
