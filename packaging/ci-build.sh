#!/bin/sh
# Build python3-netgear-switch-library (.deb) inside a Debian container. Invoked
# by .github/workflows/deb.yml once per suite as:
#   docker run --rm -v "$PWD:/src" -w /src debian:trixie sh packaging/ci-build.sh
# and reproducible locally the same way. Writes the resulting .deb files to
# /src/built-debs (bind-mounted to the host/runner).
set -eux

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  build-essential ca-certificates git \
  dpkg-dev debhelper dh-python pybuild-plugin-pyproject \
  python3-all python3-hatchling python3-hatch-vcs python3-setuptools-scm

# dpkg-buildpackage / git refuse to operate on a repo owned by another uid.
git config --global --add safe.directory /src

# Rolling release: derive the version from git and regenerate the changelog.
python3 packaging/deb-version.py --write-changelog

# Binary-only build, unsigned (the apt repo is signed later, in the publish job).
dpkg-buildpackage -b -us -uc

mkdir -p built-debs
cp ../*.deb built-debs/
ls -l built-debs/
