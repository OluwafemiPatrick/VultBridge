#!/bin/sh
set -eu

bundle_directory=${1:-}
manifest=${2:-}
expected_source_revision=${3:-${VULTBRIDGE_EXPECTED_SOURCE_REVISION:-}}
expected_release_version=${4:-${VULTBRIDGE_EXPECTED_RELEASE_VERSION:-}}
expected_architecture=${5:-${VULTBRIDGE_EXPECTED_ARCHITECTURE:-x86_64}}

if [ -z "$bundle_directory" ] || [ -z "$manifest" ]; then
  echo "Usage: $0 <os-bundle-directory> <release-manifest.txt>" >&2
  exit 2
fi
if [ -L "$bundle_directory" ] || [ ! -d "$bundle_directory" ] || [ -L "$manifest" ] || [ ! -f "$manifest" ]; then
  echo "The OS bundle directory and one release-manifest.txt are required." >&2
  exit 2
fi
case "$manifest" in
  "$bundle_directory"/release-manifest.txt) ;;
  *)
    echo "The manifest must be the single release-manifest.txt inside the OS bundle directory." >&2
    exit 2
    ;;
esac

if find "$bundle_directory" -type l -print | grep . >/dev/null 2>&1; then
  echo "The OS bundle contains a symbolic link." >&2
  exit 1
fi
if find "$bundle_directory" -maxdepth 1 -type f -name '*.asc' -print | grep . >/dev/null 2>&1; then
  echo "Detached release-manifest.txt.asc files are prohibited by Phase 7." >&2
  exit 1
fi

temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/vultbridge-manifest.XXXXXX")
trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM
parsed="$temporary_directory/parsed"

if ! awk -F '\t' '
  function fail(message) {
    print message > "/dev/stderr"
    failed = 1
    exit 1
  }
  NR == 1 {
    if ($0 != "VULTBRIDGE-RELEASE-MANIFEST\t2") fail("Invalid release manifest header.")
    next
  }
  !in_files {
    if ($0 == "files") {
      if (files_seen++) fail("Duplicate release manifest files section.")
      in_files = 1
      next
    }
    if (NF != 2) fail("Invalid release manifest metadata.")
    key = $1
    value = $2
    if (key !~ /^(name|version|os|architecture|sourceRevision|sourceTreeState|signatureStatus)$/) {
      fail("Unknown release manifest metadata.")
    }
    if (metadata_seen[key]++) fail("Duplicate release manifest metadata.")
    if (key == "name" && value != "VultBridge") fail("Invalid release manifest name.")
    if (key == "version" && value !~ /^[0-9]+(\.[0-9]+)*$/) fail("Invalid release manifest version.")
    if (key == "os" && value !~ /^(macos|linux)$/) fail("Invalid release manifest OS.")
    if (key == "architecture" && value != "x86_64") fail("Invalid release manifest architecture.")
    if (key == "sourceRevision" && value !~ /^[0-9a-f]{40}$/) fail("Invalid release source revision.")
    if (key == "sourceTreeState" && value !~ /^(clean|dirty)$/) fail("Invalid release source-tree state.")
    if (key == "signatureStatus" && value !~ /^(unsigned-ad-hoc|hashes-only)$/) fail("Invalid release signature status.")
    print key "\t" value > "/dev/stderr"
    next
  }
  {
    if (NF != 3) fail("Invalid release manifest archive entry.")
    hash = $1
    bytes = $2
    path = $3
    if (length(hash) != 64 || hash !~ /^[0-9a-f]+$/) fail("Invalid release manifest hash.")
    if (bytes !~ /^[0-9]+$/) fail("Invalid release manifest size.")
    if (path == "" || index(path, "/") || index(path, "\\") || index(path, "\t") ||
        index(path, "\r") || index(path, "\n") || path ~ /(^|\/)\.\.(\/|$)/ ||
        path ~ /(^|\/)\.(\/|$)/) {
      fail("Invalid release manifest archive name.")
    }
    if (archive_seen[path]++) fail("Duplicate release manifest archive.")
    print path "\t" hash "\t" bytes
    archive_count++
  }
  END {
    if (failed || !files_seen || archive_count == 0 ||
        !metadata_seen["name"] || !metadata_seen["version"] || !metadata_seen["os"] ||
        !metadata_seen["architecture"] || !metadata_seen["sourceRevision"] ||
        !metadata_seen["sourceTreeState"] || !metadata_seen["signatureStatus"]) exit 1
  }
' "$manifest" >"$parsed" 2>"$temporary_directory/metadata"; then
  echo "The release manifest is malformed." >&2
  exit 1
fi

manifest_value() {
  awk -F '\t' -v key="$1" '$1 == key {print $2}' "$temporary_directory/metadata"
}

manifest_os=$(manifest_value os)
manifest_architecture=$(manifest_value architecture)
manifest_status=$(manifest_value signatureStatus)
manifest_source_revision=$(manifest_value sourceRevision)
if [ -n "$expected_source_revision" ] && [ "$manifest_source_revision" != "$expected_source_revision" ]; then
  echo "The release manifest source revision does not match the expected revision." >&2
  exit 1
fi
manifest_version=$(manifest_value version)
if [ -n "$expected_release_version" ] && [ "$manifest_version" != "$expected_release_version" ]; then
  echo "The release manifest version does not match the expected version." >&2
  exit 1
fi
if [ "$manifest_architecture" != "$expected_architecture" ]; then
  echo "The release manifest architecture does not match the expected architecture." >&2
  exit 1
fi
bundle_os=$(basename "$bundle_directory")
if [ "$manifest_os" != "$bundle_os" ]; then
  echo "The manifest OS does not match its bundle directory." >&2
  exit 1
fi
case "$manifest_os:$manifest_status" in
  macos:unsigned-ad-hoc|linux:hashes-only) ;;
  *) echo "The manifest status is not valid for this OS." >&2; exit 1 ;;
esac

case "$manifest_os" in
  macos) expected_names="VultBridge-$manifest_architecture.zip VultBridge-$manifest_architecture.dmg" ;;
  linux) expected_names="VultBridge-$manifest_architecture.tar.gz" ;;
esac

expected_count=$(printf '%s\n' $expected_names | wc -l | tr -d '[:space:]')
actual_count=$(wc -l <"$parsed" | tr -d '[:space:]')
if [ "$expected_count" -ne "$actual_count" ]; then
  echo "The manifest does not contain exactly the required archive set." >&2
  exit 1
fi
for expected_name in $expected_names; do
  if [ "$(awk -F '\t' -v path="$expected_name" '$1 == path {count++} END {print count + 0}' "$parsed")" -ne 1 ]; then
    echo "The manifest is missing the required archive: $expected_name" >&2
    exit 1
  fi
done

hash_command=sha256sum
if ! command -v "$hash_command" >/dev/null 2>&1; then hash_command=shasum; fi
if ! command -v "$hash_command" >/dev/null 2>&1; then
  echo "Neither sha256sum nor shasum is available." >&2
  exit 2
fi

actual="$temporary_directory/actual"
for expected_name in $expected_names; do
  archive="$bundle_directory/$expected_name"
  if [ ! -f "$archive" ]; then
    echo "The required release archive is missing: $expected_name" >&2
    exit 1
  fi
  if [ "$hash_command" = "sha256sum" ]; then
    hash=$(sha256sum -- "$archive" | awk '{print $1}')
  else
    hash=$(shasum -a 256 -- "$archive" | awk '{print $1}')
  fi
  bytes=$(wc -c <"$archive" | tr -d '[:space:]')
  printf '%s\t%s\t%s\n' "$expected_name" "$hash" "$bytes" >>"$actual"
done
sort "$actual" -o "$actual"
sort "$parsed" >"$temporary_directory/expected"
if ! cmp -s "$temporary_directory/expected" "$actual"; then
  echo "OS bundle archives do not match the release manifest." >&2
  diff -u "$temporary_directory/expected" "$actual" >&2 || true
  exit 1
fi

sh "$(dirname "$0")/verify-release-archives.sh" "$bundle_directory"

unexpected=$(find "$bundle_directory" -mindepth 1 -maxdepth 1 ! -name 'release-manifest.txt' -print \
  | while IFS= read -r entry; do
      file=${entry#"$bundle_directory"/}
      is_expected=false
      for expected_name in $expected_names; do
        if [ "$file" = "$expected_name" ] && [ -f "$entry" ]; then is_expected=true; fi
      done
      if [ "$is_expected" = false ]; then printf '%s\n' "$file"; fi
    done)
if [ -n "$unexpected" ]; then
  echo "The OS bundle contains unexpected files: $unexpected" >&2
  exit 1
fi

echo "Verified $manifest_os $manifest_architecture release bundle: $manifest"
