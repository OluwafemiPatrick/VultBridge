#!/bin/sh
set -eu

bundle=${1:-build/release/app-image/VultBridge.app}
identity=${VULTBRIDGE_MACOS_SIGNING_IDENTITY:-}
team_identifier=${VULTBRIDGE_MACOS_TEAM_IDENTIFIER:-}

if [ -z "$identity" ]; then
  echo "VULTBRIDGE_MACOS_SIGNING_IDENTITY is required; refusing to create an unsigned release." >&2
  exit 2
fi
if [ -z "$team_identifier" ]; then
  echo "VULTBRIDGE_MACOS_TEAM_IDENTIFIER is required; refusing an unbound signer." >&2
  exit 2
fi
if [ ! -d "$bundle" ]; then
  echo "The macOS application bundle does not exist." >&2
  exit 2
fi

# The bundled runtime contains nested executables. Deep signing is used only after the package
# inventory has passed and is followed by strict verification; no signing key enters the workspace.
codesign --force --deep --options runtime --timestamp --sign "$identity" "$bundle"
codesign --verify --deep --strict --verbose=2 "$bundle"

details=$(codesign --display --verbose=4 "$bundle" 2>&1)
case "$details" in
  *"Signature=adhoc"*|*"TeamIdentifier=not set"*)
    echo "The macOS bundle is not signed by an identified certificate." >&2
    exit 1
    ;;
esac
actual_team_identifier=$(printf '%s\n' "$details" | sed -n 's/^TeamIdentifier=//p' | tail -n 1)
if [ -z "$actual_team_identifier" ] || [ "$actual_team_identifier" != "$team_identifier" ]; then
  echo "The macOS signing identity is not the approved team identity." >&2
  exit 1
fi

if command -v spctl >/dev/null 2>&1; then
  spctl --assess --type execute --verbose=4 "$bundle"
fi
