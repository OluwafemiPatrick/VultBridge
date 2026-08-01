# VultBridge

VultBridge is a local desktop application for storing files in a portable encrypted vault. The
project is in early MVP development.

## Requirements

- JDK 21
- macOS or Linux

The Gradle Wrapper downloads the pinned Gradle version; a separate Gradle installation is not required after initial project setup.

## Build and run

```bash
./gradlew clean build
./gradlew run
```

Format source files with:

```bash
./gradlew spotlessApply
```

Run the dependency vulnerability scan separately with:

```bash
./gradlew dependencyCheckAnalyze
```

The dependency scan downloads vulnerability data and may require an NVD API key in CI.

## Dependency policy

Runtime and build dependencies use exact versions in `build.gradle.kts`. Gradle dependency locking
is enabled for every resolvable configuration, and `gradle.lockfile` is committed. When changing a
dependency, regenerate the locks deliberately and review the resulting diff:

```bash
./gradlew dependencies --write-locks
./gradlew spotlessApply clean build
./gradlew dependencyCheckAnalyze
```

The current runtime libraries and their upstream-declared licenses are:

- OpenJFX 21.0.7 — GNU General Public License version 2 with the Classpath Exception.
- Bouncy Castle `bcprov-jdk18on` 1.84 — Bouncy Castle Licence.

Do not add or upgrade a runtime dependency without reviewing its maintenance status, license,
security advisories, transitive dependency changes, and lockfile diff.
