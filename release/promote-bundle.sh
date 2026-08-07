#!/bin/sh
set -eu

source_directory=${1:-}
destination_directory=${2:-}

if [ -z "$source_directory" ] || [ -z "$destination_directory" ]; then
  echo "Usage: $0 build/release/archives/<os> bundle/<os>" >&2
  exit 2
fi
if [ ! -d "$source_directory" ] || [ ! -f "$source_directory/release-manifest.txt" ]; then
  echo "The generated archive directory and its release-manifest.txt are required." >&2
  exit 2
fi
if [ -e "$destination_directory" ]; then
  echo "Refusing to overwrite an existing bundle directory: $destination_directory" >&2
  exit 1
fi
case "$destination_directory" in
  */macos|*/linux) ;;
  *) echo "The destination must be bundle/macos or bundle/linux." >&2; exit 2 ;;
esac
if find "$source_directory" -maxdepth 1 -type f -name '*.asc' -print | grep . >/dev/null 2>&1; then
  echo "Detached release-manifest.txt.asc files are prohibited by Phase 7." >&2
  exit 1
fi

sh "$(dirname "$0")/verify-release-manifest.sh" \
  "$source_directory" "$source_directory/release-manifest.txt"

parent_directory=$(dirname "$destination_directory")
mkdir -p "$parent_directory"
staging_parent=$(mktemp -d "$parent_directory/.vultbridge-bundle.XXXXXX")
manifest_os=$(basename "$destination_directory")
staging_directory="$staging_parent/$manifest_os"
mkdir "$staging_directory"
cleanup() { rm -rf "$staging_parent"; }
trap cleanup EXIT HUP INT TERM

manifest_architecture=$(awk -F '\t' '$1 == "architecture" {print $2}' "$source_directory/release-manifest.txt")
case "$manifest_os" in
  macos) archive_names="VultBridge-$manifest_architecture.zip VultBridge-$manifest_architecture.dmg" ;;
  linux) archive_names="VultBridge-$manifest_architecture.tar.gz" ;;
esac
for archive_name in $archive_names; do
  cp -p "$source_directory/$archive_name" "$staging_directory/$archive_name"
done
cp -p "$source_directory/release-manifest.txt" "$staging_directory/release-manifest.txt"
if find "$staging_directory" -maxdepth 1 -type f -name '*.asc' -print | grep . >/dev/null 2>&1; then
  echo "Detached release-manifest.txt.asc files are prohibited by Phase 7." >&2
  exit 1
fi
sh "$(dirname "$0")/verify-release-manifest.sh" \
  "$staging_directory" "$staging_directory/release-manifest.txt"
mv "$staging_directory" "$destination_directory"
rmdir "$staging_parent"
trap - EXIT HUP INT TERM
echo "Promoted verified $manifest_os release into $destination_directory"
