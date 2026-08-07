#!/bin/sh
set -eu

artifact=${1:-}
profile=${VULTBRIDGE_NOTARY_PROFILE:-}

if [ -z "$artifact" ] || [ -z "$profile" ]; then
  echo "Usage: VULTBRIDGE_NOTARY_PROFILE=<keychain-profile> $0 <signed-zip-or-dmg>" >&2
  exit 2
fi
if [ ! -e "$artifact" ]; then
  echo "The notarization artifact does not exist." >&2
  exit 2
fi

xcrun notarytool submit "$artifact" --keychain-profile "$profile" --wait
xcrun stapler staple "$artifact"
xcrun stapler validate "$artifact"
