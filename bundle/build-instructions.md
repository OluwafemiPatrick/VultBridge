# Building and manually promoting a VultBridge bundle

These instructions are for a source user who wants to reproduce a tester artifact. The Gradle
tasks build only the current native host and never cross-compile. They write generated app images,
archives, and manifests under `build/`; they never write or overwrite `bundle/`.

## Requirements

- Java 21 and the pinned Gradle Wrapper.
- A native supported macOS or Linux host.
- The exact local filesystem and OS row must have acceptance evidence before it is advertised as
  supported.
- Native `jlink`, `jpackage`, and archive tools available from the Java/toolchain installation.

Do not put passphrases, vaults, private keys, credentials, or private tester evidence in the source
tree or generated output.

## Generate disposable artifacts

From a clean checkout, choose a release version accepted by the native packager:

```bash
JAVA_HOME=/usr/local/opt/openjdk@21 \
  ./gradlew --no-configuration-cache -PreleaseVersion=1.0.0 releasePackage
```

The current x86_64 host produces one of these directories:

```text
build/release/archives/macos/
  VultBridge-x86_64.zip
  VultBridge-x86_64.dmg
  release-manifest.txt

build/release/archives/linux/
  VultBridge-x86_64.tar.gz
  release-manifest.txt
```

The outer archive filenames contain no version. The manifest is generated after the final archive
bytes and records the version. macOS status is `unsigned-ad-hoc`; Linux status is `hashes-only`.
No `release-manifest.txt.asc` is generated for any OS.

## Verify before promotion

Use the standalone verifier against the generated directory:

```bash
sh release/verify-release.sh \
  build/release/archives/macos \
  build/release/archives/macos/release-manifest.txt
```

It checks the exact OS archive set, version, architecture, status, source revision format, archive
hashes and sizes, symlink exclusion, and unexpected-file rejection. Inspect the app image while it
still exists under `build/release/app-image` and run the exact archive on a clean supported machine.
When verifying from the source checkout, bind the manifest to the build commit explicitly with
`VULTBRIDGE_EXPECTED_SOURCE_REVISION="$(git rev-parse HEAD)"`.

## Explicitly promote a reviewed release

The promotion destination must not already exist. This prevents a routine build or a mistaken
version from replacing a public/default bundle:

```bash
sh release/promote-bundle.sh \
  build/release/archives/macos bundle/macos
```

For Linux, run the same command with `build/release/archives/linux bundle/linux` on the native Linux
host. The script verifies the source, stages the exact archive set and one manifest, verifies the
staged copy, refuses `.asc` files, and atomically installs only a previously absent OS directory.
It does not create a detached signature.

After promotion, verify the public directory independently:

```bash
sh release/verify-release.sh bundle/macos bundle/macos/release-manifest.txt
```

Review the final archive hashes and tester evidence before committing `bundle/`. Preserve the old
bundle when replacing a release; do not use a build task to overwrite it.

## Clean generated output

Only after the promoted files are verified and their hashes are recorded:

```bash
./gradlew clean
```

This removes generated `build/` output and leaves `bundle/` untouched. Re-run the complete build from
a clean checkout to prove the generated output remains reproducible within the documented native
packaging limitations.

## Future signed macOS mode

This release does not require or claim Apple Developer ID signing or notarization. A future
credentialed release must sign and notarize the final application/package, verify the expected Team
ID and hardened runtime, staple/validate the result, then regenerate final archive hashes. It must
not relabel the current ad-hoc artifact as trusted.
