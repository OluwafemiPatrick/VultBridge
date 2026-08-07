# Dependency and licence review

This file is the release-time legal inventory for the exact runtime graph. Versions are pinned in
`build.gradle.kts` and locked in `gradle.lockfile`. `prepareReleasePackageContent` copies every
license/notice resource found in each resolved runtime JAR byte-for-byte into the application
image's `licenses/` directory. The two runtime distributions that do not carry plain-text legal
files in their runtime JARs use the committed exact texts in
`release/package-content/licenses/`.

## Runtime dependency evidence

| Resolved component | Version | Runtime use | Licence evidence shipped in the package |
|---|---:|---|---|
| OpenJFX `javafx-base`, `javafx-controls`, `javafx-graphics` | 21.0.7 | JavaFX UI and graphics | `licenses/OpenJFX-GPLv2-with-Classpath-Exception.txt`; Maven POM identifies `GPLv2+CE` and the OpenJDK legal source |
| Bouncy Castle `bcprov-jdk18on` | 1.84 | Argon2id, AEAD, HMAC, and key support | `licenses/Bouncy-Castle-License.txt`; text is the license body distributed as `org/bouncycastle/LICENSE.java` in the exact source artifact |
| Jackson `jackson-core` | 2.22.0 | Streaming CBOR parser/generator | Runtime JAR `META-INF/LICENSE`, `META-INF/NOTICE`, `META-INF/FastDoubleParser-LICENSE`, `META-INF/FastDoubleParser-ThirdParty-LICENSE`, `META-INF/Schubfach-LICENSE` |
| Jackson `jackson-databind` | 2.22.0 | Jackson runtime support | Runtime JAR `META-INF/LICENSE` and `META-INF/NOTICE` |
| Jackson `jackson-annotations` | 2.22.x locked version | Jackson runtime support | Runtime JAR legal resources copied by the same staging task |
| Jackson `jackson-dataformat-cbor` | 2.22.0 | Authenticated manifest/commit CBOR | Runtime JAR `META-INF/LICENSE` and `META-INF/NOTICE` |

The release task records the exact resolved JAR filenames in `THIRD-PARTY-NOTICES.txt`, so a
reviewer can map each generated legal file to the binary included in that application image. The
bundled Java runtime retains its own `legal/` directory and is reviewed according to the selected
JDK distribution.

## Build and verification dependencies

Gradle, the JavaFX Gradle plugin, Spotless, SpotBugs, Error Prone, OWASP Dependency-Check, JUnit,
Hamcrest, and TestFX support the build or tests. They are not copied into the application runtime
image. Their licences remain relevant to repository/CI redistribution and are not represented as
runtime dependency notices.

## Release verification

- [x] Runtime versions are explicit and dependency locking is enabled.
- [x] Package staging extracts exact runtime-JAR license and notice resources.
- [x] OpenJFX and Bouncy Castle plain-text license files are present in source and package content.
- [x] Package verification requires the notice, static licenses, and Jackson legal resources.
- [ ] OWASP Dependency-Check feed status, scan date, findings, and remediation decision.

The remaining unchecked item is intentionally separate from licence compliance: the local
Dependency-Check run may be blocked when the NVD feed requires an API key. It must be completed in
the release environment before publishing.
