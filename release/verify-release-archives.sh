#!/bin/sh
set -eu

bundle_directory=${1:-}
if [ -z "$bundle_directory" ]; then
  echo "Usage: $0 <os-bundle-directory>" >&2
  exit 2
fi
if [ -L "$bundle_directory" ] || [ ! -d "$bundle_directory" ]; then
  echo "The OS bundle directory is required." >&2
  exit 2
fi

fail() {
  echo "Archive verification failed: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "Required archive tool is unavailable: $1"
}

temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/vultbridge-archives.XXXXXX")
trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM

tab=$(printf '\t')
carriage_return=$(printf '\r')

verify_entry_names() {
  names_file=$1
  expected_root=$2
  allow_macos_metadata=$3

  [ -s "$names_file" ] || fail "Archive contains no members."
  while IFS= read -r entry || [ -n "$entry" ]; do
    case "$entry" in
      ""|/*|*\\*|*"$tab"*|*"$carriage_return"*)
        fail "Archive contains an invalid member name."
        ;;
    esac
    case "/$entry/" in
      */./*|*/../*) fail "Archive contains a traversal member: $entry" ;;
    esac
    case "$entry" in
      "$expected_root"|"$expected_root"/*) ;;
      __MACOSX|__MACOSX/*)
        [ "$allow_macos_metadata" = yes ] || fail "Archive contains an unexpected root: $entry"
        ;;
      *) fail "Archive contains an unexpected root: $entry" ;;
    esac
    case "/$entry/" in
      */AGENTS.md|*/AGENTS.md/*|*/memory|*/memory/*|*/test_files|*/test_files/*|*/.git|*/.git/*|*.vltb|*.vltb/*|*/.vltb|*/.vltb/*)
        fail "Archive contains forbidden development or vault content: $entry"
        ;;
    esac
  done <"$names_file"

  if sort "$names_file" | uniq -d | grep . >/dev/null 2>&1; then
    fail "Archive contains duplicate member names."
  fi
}

verify_zip() {
  archive=$1
  names_file="$temporary_directory/zip-names"
  details_file="$temporary_directory/zip-details"
  attributes_file="$temporary_directory/zip-attributes"

  require_command unzip
  unzip -Z1 -- "$archive" >"$names_file" 2>"$temporary_directory/zip-list-errors" ||
    fail "Unable to read ZIP central directory."
  verify_entry_names "$names_file" "VultBridge.app" yes

  unzip -Z -v -- "$archive" >"$details_file" 2>"$temporary_directory/zip-details-errors" ||
    fail "Unable to inspect ZIP entry attributes."
  entry_count=$(grep -c '^Central directory entry #' "$details_file" || true)
  grep '^  Unix file attributes ' "$details_file" >"$attributes_file" || true
  attribute_count=$(wc -l <"$attributes_file" | tr -d '[:space:]')
  [ "$entry_count" -gt 0 ] || fail "ZIP central directory contains no entries."
  [ "$entry_count" -eq "$attribute_count" ] ||
    fail "ZIP entries do not have inspectable Unix file attributes."

  while IFS= read -r attributes_line || [ -n "$attributes_line" ]; do
    mode=${attributes_line#*\(}
    mode=${mode%% octal*}
    case "$mode" in
      040[0-7][0-7][0-7]|100[0-7][0-7][0-7]) ;;
      *) fail "ZIP contains a non-regular or non-directory member." ;;
    esac
  done <"$attributes_file"
}

verify_tar() {
  archive=$1
  names_file="$temporary_directory/tar-names"
  details_file="$temporary_directory/tar-details"

  require_command tar
  tar -tzf "$archive" >"$names_file" 2>"$temporary_directory/tar-list-errors" ||
    fail "Unable to read TAR members."
  verify_entry_names "$names_file" VultBridge no

  tar -tvzf "$archive" >"$details_file" 2>"$temporary_directory/tar-details-errors" ||
    fail "Unable to inspect TAR entry types."
  names_count=$(wc -l <"$names_file" | tr -d '[:space:]')
  details_count=$(wc -l <"$details_file" | tr -d '[:space:]')
  [ "$names_count" -eq "$details_count" ] ||
    fail "TAR member listing and type listing disagree."

  while IFS= read -r details_line || [ -n "$details_line" ]; do
    mode=$(printf '%s\n' "$details_line" | cut -c1-10)
    case "$mode" in
      [d-][rwxstST-][rwxstST-][rwxstST-][rwxstST-][rwxstST-][rwxstST-][rwxstST-][rwxstST-][rwxstST-]) ;;
      *) fail "TAR contains a non-regular or non-directory member." ;;
    esac
  done <"$details_file"
}

case "$(basename "$bundle_directory")" in
  macos)
    verify_zip "$bundle_directory/VultBridge-x86_64.zip"
    require_command hdiutil
    hdiutil verify "$bundle_directory/VultBridge-x86_64.dmg" >/dev/null 2>"$temporary_directory/dmg-errors" ||
      fail "DMG integrity verification failed."
    ;;
  linux)
    verify_tar "$bundle_directory/VultBridge-x86_64.tar.gz"
    ;;
  *)
    fail "The OS bundle directory must be named macos or linux."
    ;;
esac

echo "Verified final archive members in $bundle_directory"
