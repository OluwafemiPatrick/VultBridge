# VultBridge

VultBridge is a local Java desktop application for keeping files in a portable, authenticated,
encrypted vault. A vault is one `.vltb` file protected by a user-chosen passphrase; VultBridge has
no account system, server dependency, recovery key, or passphrase-recovery service.

## Project status

VultBridge is under active MVP development and is not ready for production use.

Phases 1–4 are implemented and have completed their quality and adversarial-review gates. The
application supports the complete pre-compaction workflow end to end: create, authenticated unlock,
regular-file import, persisted flat listing, logical deletion, explicit authenticated export, lock,
reopen, and manual closed-vault backup. File content uses bounded streaming.

The codebase is ready to begin Phase 5. Compact & Replace remains unavailable until its candidate
creation, storage preflight, validation-before-removal, cancellation, and storage-failure behavior
have been implemented and verified.

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
also exposes imported-file sizes through public record framing. Rollback to an older complete valid
vault copy is not detected, and deletion does not promise secure physical erasure.

## Vault and filesystem rules

- Service operations accept only filenames with a non-empty base and the exact lowercase `.vltb`
  extension.
- Existing destinations and symbolic links are never overwritten or followed during creation.
- A persistent same-directory `<vault filename>.lock` file prevents cooperating VultBridge
  processes from opening the same vault concurrently.
- The lock file remains after close; deleting it during normal cleanup would create an inode race.
- Filesystem support fails closed. Phase 3 is verified on macOS 26.5.2 with APFS, so APFS is the
  only currently enabled filesystem type.
- Linux filesystems and removable media remain subject to the Phase 6 release-verification matrix.
- Network filesystems are unsupported.
- A failed creation may leave an incomplete `.vltb` file for manual removal. VultBridge does not
  automatically delete an uncertain pathname because Java cannot bind that deletion atomically to
  the file created by the failed operation.
- Export writes owner-only plaintext to a random create-new temporary file beside the destination,
  authenticates every vault chunk before writing it, forces and closes it, and publishes without
  overwrite. Failed or cancelled exports remove their temporary output where its captured APFS
  identity can still be established.

## Requirements

- JDK 21
- macOS with APFS for the currently verified development path

The committed Gradle Wrapper provides the pinned Gradle version; a separate Gradle installation is
not required.

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

Do not add or upgrade a runtime dependency without reviewing its maintenance status, license,
security advisories, transitive changes, and lockfile changes.

## Engineering expectations

Persistent-format and security changes require byte-exact fixtures, boundary and malformed-input
tests, failure-path cleanup tests, static analysis, and adversarial review. A passing build is a
required baseline, not proof that the software is free of security defects; independent human
review remains required before release.
