#!/bin/sh
set -eu

bundle_directory=${1:-build/release/archives/macos}
manifest=${2:-$bundle_directory/release-manifest.txt}
expected_source_revision=${VULTBRIDGE_EXPECTED_SOURCE_REVISION:-}
if [ -z "$expected_source_revision" ] && git -C "$(pwd)" rev-parse HEAD >/dev/null 2>&1; then
  expected_source_revision=$(git -C "$(pwd)" rev-parse HEAD)
fi

if [ -n "$expected_source_revision" ]; then
  sh "$(dirname "$0")/verify-release-manifest.sh" \
    "$bundle_directory" "$manifest" "$expected_source_revision"
else
  sh "$(dirname "$0")/verify-release-manifest.sh" "$bundle_directory" "$manifest"
fi

# The archive verifier proves the public bundle contract. Inspect the generated app image as a
# separate optional check when it is still available under build/; bundle promotion may be followed
# by the documented build cleanup, so the app image is not required for archive verification.
app_image=${VULTBRIDGE_APP_IMAGE:-build/release/app-image}
if [ -d "$app_image" ]; then
  sh "$(dirname "$0")/inspect-app-image.sh" "$app_image"
fi
