# Release tooling

The release tasks build only the current native host. They never cross-compile or imply that an
OS, filesystem, removable medium, or signing identity has been verified. All generated release
archives and manifests stay under `build/` by default. Gradle never writes or overwrites `bundle/`.

## Build generated release artifacts

Use a native host and an explicit packager version. macOS creates a `.zip` and `.dmg`; Linux creates
a `.tar.gz`. The outer filenames intentionally contain no release version; the one OS manifest
records it:

```bash
./gradlew --no-configuration-cache -PreleaseVersion=1.0.0 releasePackage
```

Expected output on the current x86_64 hosts:

```text
build/release/archives/macos/
  VultBridge-x86_64.zip
  VultBridge-x86_64.dmg
  release-manifest.txt

build/release/archives/linux/
  VultBridge-x86_64.tar.gz
  release-manifest.txt
```

Only the directory for the native host is generated. A macOS build does not create a Linux bundle,
and a Linux build does not create a macOS bundle. Do not rename a host artifact and call it a
cross-platform release.

Inspect and verify generated output before any promotion:

```bash
VULTBRIDGE_EXPECTED_RELEASE_VERSION=1.0.0 \
VULTBRIDGE_EXPECTED_ARCHITECTURE=x86_64 \
VULTBRIDGE_EXPECTED_SOURCE_REVISION="$(git rev-parse HEAD)" \
  sh release/verify-release.sh build/release/archives/macos \
  build/release/archives/macos/release-manifest.txt
```

The verifier checks the exact archive set, numeric manifest version/platform/architecture/status,
source revision, byte sizes, SHA-256 hashes, absence of symlinks, and rejection of
`release-manifest.txt.asc`. It does not hash the manifest itself, avoiding a circular value. The
expected values bind verification to a particular source checkout and release inventory. Public
bundle verification omits those bindings because the bundle may be committed in a later
artifact-only commit than the source revision that built its application bytes.

## Explicit manual promotion into `bundle/`

`bundle/` is reserved for reviewed public artifacts. The normal Gradle build does not create it or
overwrite existing contents. After reviewing and testing the generated directory, promote it
explicitly:

```bash
sh release/promote-bundle.sh \
  build/release/archives/macos bundle/macos
```

The script refuses an existing destination, copies only the expected archives and the corresponding
single `release-manifest.txt`, verifies the staged copy, and removes its temporary staging directory.
It never creates a `.asc` file. To replace a published bundle, preserve the old directory, review
the replacement separately, and choose the final destination deliberately; do not ask a build task
to overwrite it.

After promotion, verify using only the public bundle:

```bash
sh release/verify-release.sh bundle/macos bundle/macos/release-manifest.txt
```

Only after hashes and tests are recorded may generated output be cleaned:

```bash
./gradlew clean
```

The committed `bundle/` files are not under `build/` and are not removed by that command.

## macOS signing status

The current release mode is explicitly `unsigned-ad-hoc` because no Apple Developer ID identity or
notarization credentials are available. This is not an Apple-trusted or notarized release. Testers
must follow the user-controlled macOS approval flow documented in `bundle/README.md` when Gatekeeper
blocks first launch.

The future credentialed path remains available for a separately approved release:

```bash
VULTBRIDGE_MACOS_SIGNING_IDENTITY='Developer ID Application: ...' \
VULTBRIDGE_MACOS_TEAM_IDENTIFIER='TEAMID1234' \
  sh release/sign-macos.sh build/release/app-image/VultBridge.app
```

After signing, rebuild the final archive, regenerate the build manifest, and independently verify
the signed bundle. Notarization/stapling must use an external keychain profile and must be completed
before final archive hashing. The signed path never treats an ad-hoc signature as success.

## Linux integrity status

The current Linux release mode is `hashes-only`. No detached GPG signature or
`release-manifest.txt.asc` is generated for any OS bundle. Hashes protect against accidental or
post-download modification only when the manifest itself was obtained through a trusted channel.
Signing credentials and keys are not part of this repository or the bundle.
