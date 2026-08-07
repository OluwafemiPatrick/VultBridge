# Release tooling

Scripts for building, inspecting, verifying, and promoting the native packages produced under
`build/release/`. The end-to-end workflow is documented in
[`bundle/build-instructions.md`](../bundle/build-instructions.md).

## Verification

Verify an archive directory and its manifest:

```bash
sh release/verify-release.sh \
  build/release/archives/macos \
  build/release/archives/macos/release-manifest.txt
```

Use the corresponding `linux` directory on Linux. `verify-release.sh` validates the manifest and
then checks archive members; it also inspects `build/release/app-image` when that directory exists.
The manifest records the package version, OS, architecture, source revision, archive hashes, and
archive sizes.

Inspect an app image directly:

```bash
sh release/inspect-app-image.sh build/release/app-image
```

After a signed macOS build, verify the application bundle and its team identifier:

```bash
VULTBRIDGE_MACOS_TEAM_IDENTIFIER=TEAMID1234 \
  sh release/verify-macos.sh build/release/app-image/VultBridge.app
```

## Promotion

Copy a verified host package into the reviewed repository bundle:

```bash
sh release/promote-bundle.sh \
  build/release/archives/macos bundle/macos
```

The destination must not already exist. The script copies only the expected archives and the one
manifest, verifies the staged copy, and installs it atomically.

## macOS release helpers

The repository includes optional helpers for a credentialed macOS release. They operate on the
generated app image or final package and require credentials configured on the build machine:

```bash
sh release/sign-macos.sh build/release/app-image/VultBridge.app

VULTBRIDGE_NOTARY_PROFILE=profile-name \
  sh release/notarize-macos.sh \
  build/release/archives/macos/VultBridge-x86_64.dmg
```

After changing the app or package, rebuild the final archive and regenerate its manifest before
promotion.
