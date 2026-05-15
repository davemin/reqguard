#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_ROOT="$ROOT/build/deb"
VERSION="0.3.20"
PKG_ROOT="$BUILD_ROOT/reqguard_${VERSION}_all"
PYTHON_DIST="$PKG_ROOT/usr/lib/python3/dist-packages"

rm -rf "$BUILD_ROOT"
mkdir -p \
  "$PKG_ROOT/DEBIAN" \
  "$PYTHON_DIST" \
  "$PKG_ROOT/usr/bin" \
  "$PKG_ROOT/usr/share/reqguard" \
  "$PKG_ROOT/lib/systemd/system" \
  "$PKG_ROOT/var/lib/reqguard"

cp -R "$ROOT/src/reqguard" "$PYTHON_DIST/reqguard"
install -m 0755 "$ROOT/packaging/bin/reqguard" "$PKG_ROOT/usr/bin/reqguard"
install -m 0644 "$ROOT/packaging/default/reqguard" "$PKG_ROOT/usr/share/reqguard/reqguard.default"
install -m 0644 "$ROOT/packaging/systemd/reqguard-firewall.service" \
  "$PKG_ROOT/lib/systemd/system/reqguard-firewall.service"
install -m 0644 "$ROOT/packaging/debian/control" "$PKG_ROOT/DEBIAN/control"
install -m 0755 "$ROOT/packaging/debian/preinst" "$PKG_ROOT/DEBIAN/preinst"
install -m 0755 "$ROOT/packaging/debian/postinst" "$PKG_ROOT/DEBIAN/postinst"

dpkg-deb --build "$PKG_ROOT" "$BUILD_ROOT/reqguard_${VERSION}_all.deb"
echo "$BUILD_ROOT/reqguard_${VERSION}_all.deb"
