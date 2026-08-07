# VultBridge tester bundles

This directory contains manually reviewed public release artifacts. A normal Gradle build writes
only to `build/`; it never creates or overwrites these files. Each OS directory has one
`release-manifest.txt` shared by that OS's archives. The manifest records the release version,
source revision, distribution status, archive sizes, and SHA-256 hashes.

## Choose an artifact

- macOS: use `macos/VultBridge-x86_64.dmg` for a conventional disk-image installation, or
  `macos/VultBridge-x86_64.zip` to extract the application directly.
- Linux: use `linux/VultBridge-x86_64.tar.gz` when that directory has been independently built and
  tested on the supported Linux environment.

The filename intentionally has no version. Read the matching OS `release-manifest.txt` for the
version and confirm that the archive filename, byte size, and SHA-256 value match before launching.
Do not use an archive from one OS directory on another OS.

## Verify an archive without the source checkout

From the repository or downloaded bundle directory, calculate the archive hash and byte count with
the host tools, then compare both values with the matching manifest line:

```bash
shasum -a 256 bundle/macos/VultBridge-x86_64.zip
wc -c < bundle/macos/VultBridge-x86_64.zip
```

Linux systems may use `sha256sum` instead of `shasum`. The manifest itself is intentionally not
listed in its own file entries, so there is no circular self-hash. This release produces no
`release-manifest.txt.asc` file for either OS. Hashes provide integrity evidence only when this
manifest was obtained through a trusted channel.

## Launch on macOS

1. Open the `.dmg` and drag `VultBridge.app` to a user-writable application location, or extract
   the `.zip` and open the application from the extracted directory.
2. The current macOS artifact is explicitly `unsigned-ad-hoc`; it is not Apple Developer ID signed
   or notarized. macOS may block the first launch.
3. If macOS presents a security warning, cancel, open System Settings → Privacy & Security, review
   the warning, and use the user-controlled Open Anyway action only if you trust the artifact and
   have independently checked its manifest. A warning dismissal is not a signature or a security
   guarantee.
4. Do not move individual files out of the application bundle. The packaged runtime is part of the
   application.

## Use the MVP safely

VultBridge stores one flat encrypted `.vltb` file. It does not mount a drive, create folders, inspect
archives, or provide recovery. Import regular files; archive a directory outside VultBridge first if
its hierarchy must be preserved. Exported files are ordinary plaintext host files.

Deletion is logical: deleted ciphertext may remain in the vault or filesystem remnants. Compact &
Replace creates and validates a replacement, and the current portable implementation retains the
source when identity-safe removal cannot be proven. A forgotten passphrase cannot be recovered.
While unlocked, a compromised host can observe passphrases, keys, plaintext, and application memory.

Use only the filesystem and OS combinations listed as verified in `docs/release/support-matrix.md`.
Network storage and Windows are outside the MVP support claim. Do not submit vaults, passphrases,
keys, plaintext files, or complete private paths in tester reports.

## Rebuild from source

Source users should follow [`build-instructions.md`](build-instructions.md). It builds disposable
artifacts under `build/`, verifies them, and requires an explicit refusal-by-default promotion before
anything enters this directory.
