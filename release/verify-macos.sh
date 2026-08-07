#!/bin/sh
set -eu

bundle=${1:-build/release/app-image/VultBridge.app}
team_identifier=${VULTBRIDGE_MACOS_TEAM_IDENTIFIER:-}
if [ ! -d "$bundle" ]; then
  echo "The macOS application bundle does not exist." >&2
  exit 2
fi
if [ -z "$team_identifier" ]; then
  echo "VULTBRIDGE_MACOS_TEAM_IDENTIFIER is required for independent verification." >&2
  exit 2
fi

details=$(codesign --display --verbose=4 "$bundle" 2>&1)
case "$details" in
  *"Signature=adhoc"*|*"TeamIdentifier=not set"*)
    echo "The macOS bundle has no identified release signature." >&2
    exit 1
    ;;
esac
actual_team_identifier=$(printf '%s\n' "$details" | sed -n 's/^TeamIdentifier=//p' | tail -n 1)
if [ -z "$actual_team_identifier" ] || [ "$actual_team_identifier" != "$team_identifier" ]; then
  echo "The macOS bundle signer is not the approved team identity." >&2
  exit 1
fi
codesign --verify --deep --strict --verbose=2 "$bundle"
spctl --assess --type execute --verbose=4 "$bundle"
