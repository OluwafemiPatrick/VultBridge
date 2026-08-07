# VultBridge

VultBridge is a local Java desktop application for keeping files in a portable, authenticated,
encrypted vault. A vault is one `.vltb` file protected by a user-chosen passphrase; VultBridge has
no account system, server dependency, recovery key, or passphrase-recovery service.

## MVP scope

The MVP is intentionally narrow:

- One flat list of files with no folders or directory import.
- At most 10,000 live files and 100 GiB of live file data per vault.
- Individual regular-file import and explicit export.
- Logical deletion followed by optional Compact & Replace space reclamation.
- Manual encrypted backup by copying a closed `.vltb` file.
- macOS and Linux as the eventual release targets.

Files that need a directory hierarchy should be archived before import. VultBridge does not create,
inspect, or extract archives.

## Security model

VultBridge v1 uses:

- Argon2id v1.3 for passphrase-based key derivation.
- ChaCha20-Poly1305 for authenticated encryption.
- HKDF-SHA-256 for key separation.
- HMAC-SHA-256 for authenticated mutable header slots.
- Independent per-record keys and 4 MiB streaming FILE chunks.
- An append-only record log with two authenticated commit-pointer slots.

Passphrases must contain 8–64 printable ASCII characters. Forgotten passphrases cannot be
recovered.

VultBridge protects a locked vault from offline content disclosure and undetected modification. It
does not protect plaintext or passphrases on a compromised host while the vault is unlocked. The
host can observe the vault filename, total physical size, host timestamps, and update timing. V1
also exposes imported-file sizes through public record framing.

## Requirements

- JDK 21
- macOS 26.5.2 on local APFS, or Ubuntu 22.04.5 LTS on local ext4 for the current tested paths
- Linux overlay/virtiofs, network filesystems, removable media, and other unverified filesystem
  types remain rejected by the runtime

The committed Gradle Wrapper provides the pinned Gradle version; a separate Gradle installation is
not required.

Read the complete [user guide](docs/user-guide.md) for the passphrase/trust model, metadata
disclosures, logical deletion, Compact & Replace, manual backups, troubleshooting, and support
boundaries. Public tester bundles are under `bundle/` when explicitly promoted; release verification
records are under `docs/release/`.

## Build and run

On systems where Java 21 is not already selected, point `JAVA_HOME` at the JDK before invoking the
wrapper.

```bash
export JAVA_HOME=/usr/local/opt/openjdk@21
./gradlew run
```

Run the complete required quality gate with:

```bash
JAVA_HOME=/usr/local/opt/openjdk@21 ./gradlew spotlessApply clean build
```

Run only the tests with:

```bash
JAVA_HOME=/usr/local/opt/openjdk@21 ./gradlew test
```

Run dependency vulnerability analysis separately with:

```bash
JAVA_HOME=/usr/local/opt/openjdk@21 ./gradlew dependencyCheckAnalyze
```

OWASP Dependency-Check downloads current vulnerability data and may require an NVD API key.

## Source layout

```text
src/main/java/com/vultbridge/
  app/       application entry point and state transitions
  crypto/    passphrase handling, key hierarchy, and cryptographic primitives
  platform/  file dialogs, filesystem policy, source inspection, export targets, and sidecar locking
  service/   background work, sessions, creation/unlock, import, export, and logical deletion
  ui/        JavaFX screens, dialogs, and metadata-only view models
  vault/     v1 binary format, records, CBOR, commits, and durability protocol
```

The `vault` and `crypto` packages remain independent of JavaFX. UI state contains metadata only and
must not receive passphrases, keys, complete manifest plaintext, or file-content buffers.

## Dependencies and reproducibility

Runtime and build dependencies use exact versions. Gradle dependency locking applies to every
resolvable configuration, and lockfiles are committed. The principal runtime libraries are:

- OpenJFX 21.0.7 — GNU GPL v2 with the Classpath Exception.
- Bouncy Castle `bcprov-jdk18on` 1.84 — Bouncy Castle Licence.
- Jackson CBOR 2.22.0 — Apache License 2.0.

After an intentional dependency change, regenerate locks and review the resulting diff:

```bash
./gradlew dependencies --write-locks
./gradlew spotlessApply clean build
./gradlew dependencyCheckAnalyze
```

Build current-host release archives only with an explicit native-packager version:

```bash
./gradlew --no-configuration-cache -PreleaseVersion=1.0.0 releasePackage
```

This creates a `jlink` runtime, a `jpackage` app-image, final host archives, a single OS SHA-256
manifest, and a package-content check under `build/release/`. It does not sign or notarize the
result. Review the generated files, then use the explicit promotion instructions in
`release/README.md` to copy them into `bundle/`; no Gradle task writes to `bundle/`.

Do not add or upgrade a runtime dependency without reviewing its maintenance status, license,
security advisories, transitive changes, and lockfile changes.
