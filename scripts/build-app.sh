#!/bin/bash
set -euo pipefail

# Building/signing does not install the privileged helper or change network rules.
project_dir="$(cd "$(dirname "$0")/.." && pwd)"
cd "$project_dir"
configuration="${CONFIGURATION:-release}"
case "$configuration" in release|debug) ;; *) echo 'CONFIGURATION must be release or debug.' >&2; exit 1 ;; esac

swift build -c "$configuration" --product EnsureVPN
swift build -c "$configuration" --product EnsureVPNHelper
binary_dir="$(swift build -c "$configuration" --show-bin-path)"
mkdir -p "$project_dir/dist"
staging_dir="$(mktemp -d "$project_dir/dist/.bundle.XXXXXX")"

# Cleanup is deliberately limited to this script's own generated staging directory.
cleanup() {
    python3 - "$staging_dir" "$project_dir/dist" <<'PY'
import pathlib
import shutil
import sys
stage = pathlib.Path(sys.argv[1])
dist = pathlib.Path(sys.argv[2]).resolve()
if stage.parent.resolve() != dist or not stage.name.startswith('.bundle.') or stage.is_symlink():
    raise SystemExit('Refusing to clean an unexpected staging path.')
if stage.exists():
    shutil.rmtree(stage)
PY
}
trap cleanup EXIT

app_bundle="$staging_dir/Latch.app"
helper_binary="$app_bundle/Contents/Helpers/EnsureVPNHelper"
mkdir -p "$app_bundle/Contents/MacOS" "$app_bundle/Contents/Resources" "$app_bundle/Contents/Helpers"
cp "$binary_dir/EnsureVPN" "$app_bundle/Contents/MacOS/EnsureVPN"
cp "$binary_dir/EnsureVPNHelper" "$helper_binary"
cp Packaging/App-Info.plist "$app_bundle/Contents/Info.plist"
cp README.md "$app_bundle/Contents/Resources/README.md"

if [[ -n "${SIGNING_IDENTITY:-}" && "$SIGNING_IDENTITY" != '-' ]]; then
    # Normal application signing is optional. PF does not require Network Extension
    # entitlements, provisioning profiles, or an Apple Developer membership.
    /usr/bin/codesign --force --timestamp --options runtime --sign "$SIGNING_IDENTITY" "$helper_binary"
    /usr/bin/codesign --force --timestamp --options runtime --sign "$SIGNING_IDENTITY" "$app_bundle"
else
    /usr/bin/codesign --force --sign - "$helper_binary"
    /usr/bin/codesign --force --sign - "$app_bundle"
fi
/usr/bin/codesign --verify --deep --strict "$app_bundle"

# Replace only the known generated app bundle, never an arbitrary caller path.
python3 - "$app_bundle" "$project_dir/dist" <<'PY'
import pathlib
import shutil
import sys
source = pathlib.Path(sys.argv[1])
dist = pathlib.Path(sys.argv[2]).resolve()
if source.name != 'Latch.app' or source.parent.parent.resolve() != dist or source.is_symlink():
    raise SystemExit('Refusing to publish an unexpected app path.')
destination = dist / 'Latch.app'
if destination.is_symlink() or (destination.exists() and not destination.is_dir()):
    raise SystemExit('Refusing to replace an unexpected dist/Latch.app entry.')
if destination.exists():
    shutil.rmtree(destination)
source.rename(destination)
PY

printf 'Built: %s\n' "$project_dir/dist/Latch.app"
printf '%s\n' 'Local PF build: no Apple signing account required. Enabling Always-on VPN requests administrator authorization.'
