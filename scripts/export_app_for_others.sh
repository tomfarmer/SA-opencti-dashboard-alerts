#!/usr/bin/env bash
set -euo pipefail

# Build a distributable tar.gz with the desired app folder name.

APP_SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
APP_NAME_SRC="$(basename "$APP_SRC_DIR")"
APP_NAME_DST="SA-opencti-threat-match-dashboard"
VERSION="$(awk -F'= ' '/^version/{print $2;exit}' "$APP_SRC_DIR/default/app.conf" || echo "0.0.0")"
DIST_DIR="$APP_SRC_DIR/dist"

mkdir -p "$DIST_DIR"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

cp -a "$APP_SRC_DIR" "$TMPDIR/$APP_NAME_DST"

# Remove build artifacts and VCS if any
rm -rf "$TMPDIR/$APP_NAME_DST/dist" || true
rm -rf "$TMPDIR/$APP_NAME_DST/.git" "$TMPDIR/$APP_NAME_DST/.github" || true

tar -C "$TMPDIR" -czf "$DIST_DIR/${APP_NAME_DST}-${VERSION}.tar.gz" "$APP_NAME_DST"

echo "Built: $DIST_DIR/${APP_NAME_DST}-${VERSION}.tar.gz"
