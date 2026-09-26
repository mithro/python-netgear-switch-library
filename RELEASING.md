# Releasing

This project is a **rolling release**. There are no manual version bumps: the
version is derived from `git describe` (`hatch-vcs` for the wheel,
[apt-repo-action](https://github.com/mithro/apt-repo-action)'s shared
`scripts/deb-version.py` for the `.deb`) — `X.Y` at a `vX.Y` tag,
`X.Y.postN` N commits after it, and for the `.deb` the suite's `~deb<R>`
(`~deb12` bookworm, `~deb13` trixie, `~deb14` forky, none on sid) — and
**every green merge to `main` publishes new packages** automatically:

- `.github/workflows/deb.yml` ("Debian packages") — its `test` job runs the
  gates (ruff, mypy --strict, pytest with coverage >= 90, docs build) on every
  push and PR; a green run is what "mergeable" means. Then `build-deb` builds
  the `.deb` for bookworm, trixie, forky and sid with apt-repo-action's shared
  `build-deb` action and install-tests it (`packaging/install-test.sh`), and,
  on `main` only, `publish-apt` republishes the signed apt repo on GitHub
  Pages. A pull request builds preview packages (`~pr<N>`, sorting below
  `main`'s) as workflow artifacts and publishes nothing.
- `.github/workflows/publish-pypi.yml` — builds and uploads the wheel + sdist to
  PyPI when "Debian packages" **succeeds** on `main` (`workflow_run`; a failed
  or cancelled run publishes nothing, and the checkout is pinned to the SHA it
  validated).

`debian/changelog` is not committed: the build writes it, with the version.

Merges to `main` MUST use `--no-ff` merge commits so history stays linear per PR.

## Tags

Tags are the only human input to the version. `v0.0` sits on the root commit
(so `git describe` works from the start of history, per the repo-setup
guidance) and `v0.1` marks where the CI-gated pipeline landed (2026-08-22). The
fallback before any tag existed was `0.0.post<commit count>`, which reached
`0.0.post405` on PyPI; `v0.1` was chosen because it sorts above that in both
PEP 440 and Debian ordering, whereas counting from a root tag alone would have
re-issued `0.0.post404`/`405` (and `skip-existing` would have silently dropped
the upload).

To cut a new series, push an annotated `vX.Y` tag on `main` (a GitHub tag
ruleset only admits `vXX.ZZZ`-shaped tags) — the next green CI run publishes
`X.Y`, and every commit after it `X.Y.postN`. Never move or delete a tag that
has been published from.

## One-time human setup

These steps are done ONCE by a maintainer. **No secret or key is ever committed
to the repo.** Until they are done, the workflows run but the publish/sign steps
are safely gated (PyPI publish needs the trusted publisher; signing is skipped if
`APT_GPG_PRIVATE_KEY` is unset).

### 1. PyPI trusted publishing (OIDC)

1. Create the project `python-netgear-switch-library` on https://pypi.org (or
   let the first trusted-publisher upload create it via a pending publisher).
2. On PyPI, go to the project (or your account's "Publishing" page) and add a
   **Trusted Publisher** with:
   - Owner: `mithro`
   - Repository: `python-netgear-switch-library`
   - Workflow filename: `publish-pypi.yml`
   - Environment name: `pypi`
3. In the GitHub repo, create an **Environment** named `pypi`
   (Settings → Environments → New environment). No secrets needed — OIDC handles
   auth. Optionally add required reviewers to gate uploads.

After this, the next push to `main` uploads to PyPI. `skip-existing: true` makes
re-runs idempotent.

### 2. apt repo GPG signing key

1. Generate a signing key locally (RSA 4096, no passphrase so CI can use it
   unattended; keep the private key OFFLINE, never in the repo):

   ```sh
   gpg --batch --gen-key <<EOF
   %no-protection
   Key-Type: RSA
   Key-Length: 4096
   Name-Real: python-netgear-switch-library apt repo
   Name-Email: me@mith.ro
   Expire-Date: 0
   %commit
   EOF
   ```

2. Export the private key (armored) and add it as the GitHub Actions secret
   `APT_GPG_PRIVATE_KEY` (Settings → Secrets and variables → Actions → New
   repository secret):

   ```sh
   gpg --armor --export-secret-keys me@mith.ro | pbcopy   # or xclip / paste manually
   ```

   `mithro/apt-repo-action`'s publish workflow imports this key and publishes
   the matching public key as `python-netgear-switch-library.gpg` (binary) and
   `.asc` (armoured) at the apt repo root; users install the `.gpg` into
   `/etc/apt/keyrings/` (see the repo's index page).

3. **Until `APT_GPG_PRIVATE_KEY` is set, the publish job fails.**
   `mithro/apt-repo-action` refuses to publish an unsigned repository, so
   nothing is deployed rather than something consumers would have to trust
   with `[trusted=yes]`.

### 3. GitHub Pages

1. Settings → Pages → Source: **GitHub Actions**.
2. The `deb.yml` `publish-apt` job deploys the apt repo to
   `https://mith.ro/python-netgear-switch-library/`. It targets the
   `github-pages` deployment environment, which GitHub creates automatically
   once Pages is enabled — no separate environment setup is needed for this
   one (unlike the `pypi` environment above, which must be created by hand).

## Verifying a release

- PyPI: check https://pypi.org/project/python-netgear-switch-library/ for the new
  `X.Y.postN` version (matches `git describe --tags` on `main`, e.g. `v0.1-3-g…`
  → `0.1.post3`).
- apt: `sudo apt update && apt-cache policy python3-netgear-switch-library` on a
  Debian bookworm/trixie/forky/sid box configured per the README. Before the GPG key is set
  (see step 2 above), expect `apt update` to fail with a signature error for
  this repo — that confirms the fail-closed behavior is working, not that
  something is broken.
