#!/bin/sh
# Build the install bundle: dist/fr-os-ai-perimeter-<version>.tar.gz holding
# install.sh, the wheel, the systemd units and their SHA256SUMS.
#
#   installer/make-bundle.sh [output-dir]
#
# The wheel is built without its dependencies (--no-deps): on the router,
# FR_OS's pinned packages are all the AI-Perimeter uses.
set -eu

ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
OUT=${1:-$ROOT/dist}
PYTHON=${PYTHON:-python3}

version=$("$PYTHON" -c 'import tomllib, sys; print(tomllib.load(open(sys.argv[1], "rb"))["project"]["version"])' \
    "$ROOT/pyproject.toml")
name=fr-os-ai-perimeter-$version
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

stage=$work/$name
mkdir -p "$stage/systemd/fr-webui.service.d" "$stage/patches"
"$PYTHON" -m pip wheel --quiet --no-deps -w "$stage" "$ROOT"
install -m 0755 "$ROOT/installer/install.sh" "$stage/install.sh"
install -m 0644 "$ROOT/systemd/fr-ai-assist.socket" "$ROOT/systemd/fr-ai-assist.service" \
    "$ROOT/systemd/fr-ai-upload.service" "$stage/systemd/"
install -m 0644 "$ROOT/systemd/fr-webui.service.d/ai-perimeter.conf" "$stage/systemd/fr-webui.service.d/"
install -m 0644 "$ROOT/integration/fr_os/conntrack-bytes.patch" "$stage/patches/"
(cd "$stage" && sha256sum -- *.whl install.sh systemd/fr-ai-assist.socket systemd/fr-ai-assist.service \
    systemd/fr-ai-upload.service systemd/fr-webui.service.d/ai-perimeter.conf \
    patches/conntrack-bytes.patch > SHA256SUMS)

mkdir -p "$OUT"
tar -C "$work" --owner=0 --group=0 --numeric-owner --sort=name -czf "$OUT/$name.tar.gz" "$name"
(cd "$OUT" && sha256sum -- "$name.tar.gz" > "$name.tar.gz.sha256")
echo "$OUT/$name.tar.gz"
