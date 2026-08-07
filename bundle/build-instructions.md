# Build a VultBridge package

Developer instructions for producing a native package from this checkout. Builds are host-native:
run them on the macOS or Linux system you intend to package. Generated files stay under `build/`.

## Requirements

- JDK 21
- The Gradle Wrapper
- A supported macOS or Linux host
- Native `jlink`, `jpackage`, and archive tools from the JDK/OS

## Build

Choose a release version and run:

```bash
release_version=1.0.0
JAVA_HOME=/path/to/jdk-21 \
  ./gradlew --no-configuration-cache \
  -PreleaseVersion="$release_version" releasePackage
```

The task builds the app image, creates the final archive for the current host, writes one
`release-manifest.txt`, and validates the package contents.

Expected output for x86_64 hosts:

```text
build/release/archives/macos/
  VultBridge-x86_64.zip
  VultBridge-x86_64.dmg
  release-manifest.txt

build/release/archives/linux/
  VultBridge-x86_64.tar.gz
  release-manifest.txt
```

Only the directory for the current host is produced. A macOS build does not create a Linux
package, and a Linux build does not create a macOS package.

## Verify

Verify the generated directory before sharing or promoting it:

```bash
os=macos
VULTBRIDGE_EXPECTED_RELEASE_VERSION="$release_version" \
VULTBRIDGE_EXPECTED_ARCHITECTURE=x86_64 \
VULTBRIDGE_EXPECTED_SOURCE_REVISION="$(git rev-parse HEAD)" \
  sh release/verify-release.sh \
  "build/release/archives/$os" \
  "build/release/archives/$os/release-manifest.txt"
```

Set `os=linux` on Linux. Verification checks the manifest, archive hashes and sizes, expected
archive names, archive members, symlinks, app-image contents, and unexpected files. It also binds
the result to the source revision. Promotion additionally requires a clean source tree.

## Promote a reviewed package

Promotion is explicit and never overwrites an existing directory:

```bash
sh release/promote-bundle.sh \
  build/release/archives/macos bundle/macos
```

Use `build/release/archives/linux bundle/linux` on Linux. Verify the promoted copy independently:

```bash
sh release/verify-release.sh \
  bundle/macos bundle/macos/release-manifest.txt
```

Replace `macos` with `linux` where appropriate. Clean generated files only after review:

```bash
./gradlew clean
```

`clean` removes `build/` output and does not modify `bundle/`.
