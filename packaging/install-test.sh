#!/bin/sh
# Install the built .debs into a clean debian:<suite> container, with their
# dependencies from the Debian archive, and exercise them without a switch.
# Run by .github/workflows/deb.yml's "Install test" step, and locally, as:
#   docker run --rm -v "$PWD/built-debs:/debs:ro" -v "$PWD/packaging:/packaging:ro" \
#     debian:trixie sh /packaging/install-test.sh
set -eux

export DEBIAN_FRONTEND=noninteractive
apt-get update
# Recommends too, as a plain `apt install` would: python3-httpx (the HTTP
# backend), and python3-mcp where the suite has it.
apt-get install -y /debs/*.deb

# The Python version is the package's without the Debian-only ~deb<R> and
# ~pr<P> suffixes (debian/rules strips them), and must be exactly that: the
# wheel on PyPI carries the same X.Y[.postN].
deb_version=$(dpkg-query -W -f '${Version}' python3-netgear-switch-library)
py_version=${deb_version%%~*}
python3 - "$py_version" <<'EOF'
import sys
from importlib.metadata import version

import netgear_switch
import netgear_switch.cli.main
import netgear_switch.sync_api

want = sys.argv[1]
assert netgear_switch.__version__ == want, (netgear_switch.__version__, want)
assert version("python-netgear-switch-library") == want
assert netgear_switch.__file__.startswith("/usr/lib/python3/dist-packages/"), netgear_switch.__file__
print("netgear_switch", netgear_switch.__version__, "from", netgear_switch.__file__)
EOF

# The CLI entry point, and a command that needs no switch: the model registry.
ngsw --help
models=$(ngsw models)
echo "$models"
echo "$models" | grep -q '^gsm7252ps '
echo "$models" | grep -q '^gs305ep '

# The synchronous SNMP transport shells out to net-snmp: a hard dependency.
command -v snmpget snmpbulkwalk snmpset

# The MCP server entry point is installed unconditionally; it runs when the
# suite has python3-mcp (a Recommends; sid only, so far).
command -v ngsw-mcp
if python3 -c 'import importlib.util, sys; sys.exit(importlib.util.find_spec("mcp") is None)'; then
  ngsw-mcp --help
fi

# A real round trip, with no switch: serve the in-package mock GS305EP (a Plus
# switch, driven over its HTTP web UI) on port 80, where ngsw looks for it,
# and read its ports back through the HTTP backend (python3-httpx, a
# Recommends every suite has).
cd "$(mktemp -d)"
ngsw serve --model gs305ep --http-port 80 > serve.log 2>&1 &
serve=$!
tries=0
until grep -q '^serving ' serve.log; do
  tries=$((tries + 1))
  if [ "$tries" -gt 60 ] || ! kill -0 "$serve"; then
    cat serve.log
    exit 1
  fi
  sleep 0.5
done
cat serve.log
ports=$(ngsw --host 127.0.0.1 --model gs305ep --http-password password --backend http ports)
echo "$ports"
kill "$serve"
# The mock's seeded state: five ports, port 1 up at 1000 Mb/s.
echo "$ports" | grep -Eq '^1 +Port 1 +up +enabled +1000 '
test "$(echo "$ports" | grep -Ec '^[1-5] +Port ')" -eq 5

echo "install test passed: python3-netgear-switch-library $deb_version"
