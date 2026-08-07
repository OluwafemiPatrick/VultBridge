#!/bin/sh
set -eu

artifact=${1:-build/release/app-image}

if [ ! -d "$artifact" ]; then
  echo "The application image directory does not exist." >&2
  exit 2
fi

runtime=$(find "$artifact" -type f -path '*/runtime*/bin/java' -print | head -n 1)
config=$(find "$artifact" -type f -name 'VultBridge.cfg' -print | head -n 1)
if [ -z "$runtime" ] || [ -z "$config" ]; then
  echo "The packaged runtime or launcher configuration is missing." >&2
  exit 1
fi
if [ ! -x "$runtime" ]; then
  echo "The packaged Java launcher is not executable." >&2
  exit 1
fi

"$runtime" --version
grep -F -- 'com.vultbridge/com.vultbridge.app.VultBridgeApplication' "$config" >/dev/null
find "$artifact" -type f -name 'THIRD-PARTY-NOTICES.txt' -print | grep . >/dev/null
if find "$artifact" -type l -print | grep . >/dev/null; then
  echo "The package contains a symbolic link." >&2
  exit 1
fi

if find "$artifact" -type f \( -name '*.vltb' -o -name 'AGENTS.md' -o -path '*/memory/*' -o -path '*/.git/*' \) -print | grep . >/dev/null; then
  echo "The package contains development or vault content." >&2
  exit 1
fi
