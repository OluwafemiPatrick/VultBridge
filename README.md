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
