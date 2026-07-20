# Releasing

This project is a **rolling release**. There are no tags and no manual version
bumps: the version is derived from git (`hatch-vcs` for the wheel,
`packaging/deb-version.py` for the `.deb`), and **every merge to `main`
publishes new packages** automatically:

- `.github/workflows/ci.yml` — runs the gates (ruff, mypy --strict, pytest with
  coverage >= 90) on every push and PR. A green run is what "mergeable" means.
- `.github/workflows/publish-pypi.yml` — builds and uploads the wheel + sdist to
  PyPI on every push to `main`.
- `.github/workflows/deb.yml` — builds `.deb`s for trixie + sid and republishes
  the signed apt repo on GitHub Pages on every push to `main`.

Merges to `main` MUST use `--no-ff` merge commits so history stays linear per PR.

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

   The workflow imports this key and exports the matching public key to
   `netgear-switch.gpg` at the apt repo root, which users install into
   `/etc/apt/keyrings/`.

3. **Until `APT_GPG_PRIVATE_KEY` is set, the apt repo is published UNSIGNED and
   is unusable by design.** The `deb.yml` "Sign repo" step is gated on
   `if: env.GPG_PRIVATE_KEY != ''`, so with no secret it is skipped entirely:
   no `Release.gpg`, no `InRelease`, and no `netgear-switch.gpg` public key are
   published. This is not a bug — it is intentional: the README and
   `packaging/apt-index.html` both tell users to configure their `sources.list`
   entry with `[signed-by=/etc/apt/keyrings/netgear-switch.gpg]` (never
   `[trusted=yes]`), so `apt update` will fail closed (unable to fetch the
   missing/invalid signature) rather than silently accepting an unsigned repo.
   Setting this secret is therefore **required** before the apt repo works at
   all, not just before it works securely.

### 3. GitHub Pages

1. Settings → Pages → Source: **GitHub Actions**.
2. The `deb.yml` `publish-apt` job deploys the apt repo to
   `https://mithro.github.io/python-netgear-switch-library/`. It targets the
   `github-pages` deployment environment, which GitHub creates automatically
   once Pages is enabled — no separate environment setup is needed for this
   one (unlike the `pypi` environment above, which must be created by hand).

## Verifying a release

- PyPI: check https://pypi.org/project/python-netgear-switch-library/ for the new
  `0.0.postN` version.
- apt: `sudo apt update && apt-cache policy python3-netgear-switch-library` on a
  Debian trixie/sid box configured per the README. Before the GPG key is set
  (see step 2 above), expect `apt update` to fail with a signature error for
  this repo — that confirms the fail-closed behavior is working, not that
  something is broken.
