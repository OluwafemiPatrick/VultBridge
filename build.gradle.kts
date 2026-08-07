import com.github.spotbugs.snom.Confidence
import com.github.spotbugs.snom.Effort
import com.github.spotbugs.snom.SpotBugsTask
import org.gradle.api.DefaultTask
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Classpath
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputDirectory
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import java.io.File
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.security.MessageDigest
import java.util.zip.ZipFile

plugins {
    application
    java
    id("org.openjfx.javafxplugin") version "0.1.0"
    id("com.diffplug.spotless") version "8.8.0"
    id("com.github.spotbugs") version "6.5.9"
    id("net.ltgt.errorprone") version "5.1.0"
    id("org.owasp.dependencycheck") version "12.2.2"
}

group = "com.vultbridge"
version = "0.1.0-SNAPSHOT"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

javafx {
    version = "21.0.7"
    modules = listOf("javafx.controls")
}

application {
    mainModule = "com.vultbridge"
    mainClass = "com.vultbridge.app.VultBridgeApplication"
}

val releaseRuntimeDependencies =
    listOf(
        "org.bouncycastle:bcprov-jdk18on:1.84",
        "com.fasterxml.jackson.dataformat:jackson-dataformat-cbor:2.22.0",
        "org.openjfx:javafx-controls:21.0.7",
    )

abstract class VerifyReleaseToolchainTask : DefaultTask() {
    @get:Input abstract val expectedJavaMajor: Property<String>

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val wrapperProperties: RegularFileProperty

    @TaskAction
    fun verify() {
        check(JavaVersion.current().majorVersion == expectedJavaMajor.get()) {
            "Phase 6 requires Java ${expectedJavaMajor.get()}; found ${JavaVersion.current()}"
        }
        check(
            wrapperProperties.asFile
                .get()
                .readText()
                .contains("gradle-8.14.5-"),
        ) {
            "The Gradle Wrapper version is not the pinned 8.14.5 release"
        }
    }
}

abstract class VerifyReleaseDependenciesTask : DefaultTask() {
    @get:Input abstract val requiredCoordinates: ListProperty<String>

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val buildScript: RegularFileProperty

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val dependencyLock: RegularFileProperty

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val settingsDependencyLock: RegularFileProperty

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val licenseReview: RegularFileProperty

    @get:InputDirectory
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val packageContent: DirectoryProperty

    @get:InputFiles @get:Classpath
    abstract val runtimeClasspath: ConfigurableFileCollection

    @TaskAction
    fun verify() {
        val buildText = buildScript.asFile.get().readText()
        val lockText = dependencyLock.asFile.get().readText()
        check(settingsDependencyLock.asFile.get().isFile) {
            "The settings dependency lockfile is missing"
        }
        check(licenseReview.asFile.get().isFile) { "The dependency and licence review is missing" }
        val packageContentDirectory = packageContent.asFile.get()
        check(File(packageContentDirectory, "THIRD-PARTY-NOTICES.txt").isFile) {
            "The package third-party notice is missing"
        }
        listOf(
            "licenses/OpenJFX-GPLv2-with-Classpath-Exception.txt",
            "licenses/Bouncy-Castle-License.txt",
        ).forEach { relativePath ->
            check(File(packageContentDirectory, relativePath).isFile) {
                "The exact static licence text is missing: $relativePath"
            }
        }
        val reviewText = licenseReview.asFile.get().readText()
        listOf("21.0.7", "1.84", "2.22.0", "OpenJFX-GPLv2-with-Classpath-Exception.txt")
            .forEach { requiredText ->
                check(reviewText.contains(requiredText)) {
                    "The dependency licence review is incomplete: $requiredText"
                }
            }
        requiredCoordinates.get().forEach { coordinate ->
            check(buildText.contains(coordinate)) { "Runtime dependency is not pinned: $coordinate" }
            val lockCoordinate =
                coordinate.substringBeforeLast(":") + ":" + coordinate.substringAfterLast(":")
            check(lockText.contains(lockCoordinate)) {
                "Runtime dependency is absent from gradle.lockfile: $coordinate"
            }
        }
        check(!Regex("implementation\\(\\\"[^\\\"]+:\\+\\\"\\)").containsMatchIn(buildText)) {
            "Dynamic runtime dependency versions are not permitted"
        }
        check(!Regex("implementation\\(\\\"[^\\\"]+:latest[^\\\"]*\\\"\\)").containsMatchIn(buildText)) {
            "Floating runtime dependency versions are not permitted"
        }
        check(runtimeClasspath.files.isNotEmpty()) { "The runtime classpath did not resolve" }
    }
}

fun runCommand(command: List<String>) {
    val process = ProcessBuilder(command).redirectErrorStream(true).start()
    val output =
        process.inputStream
            .bufferedReader()
            .use { it.readText() }
            .trim()
    val exitCode = process.waitFor()
    check(exitCode == 0) {
        if (output.isEmpty()) {
            "Release tool failed: ${command.first()}"
        } else {
            "Release tool failed: ${command.first()}\n$output"
        }
    }
}

fun releaseHostOsName(): String =
    when {
        System.getProperty("os.name").contains("mac", ignoreCase = true) -> "macos"
        System.getProperty("os.name").contains("linux", ignoreCase = true) -> "linux"
        else -> "unsupported"
    }

fun releaseHostArchitectureName(): String =
    when (System.getProperty("os.arch").lowercase()) {
        "x86_64", "amd64" -> "x86_64"
        "aarch64", "arm64" -> "aarch64"
        else -> "unsupported"
    }

fun releaseArchiveNames(
    os: String,
    architecture: String,
): List<String> =
    when (os) {
        "macos" ->
            listOf(
                "VultBridge-$architecture.zip",
                "VultBridge-$architecture.dmg",
            )
        "linux" -> listOf("VultBridge-$architecture.tar.gz")
        else -> error("Release packaging supports macOS and Linux only; found $os")
    }

fun gitOutput(arguments: List<String>): String {
    val process =
        ProcessBuilder(listOf("git") + arguments)
            .directory(projectDir)
            .redirectErrorStream(true)
            .start()
    val output =
        process.inputStream
            .bufferedReader()
            .use { it.readText() }
            .trim()
    check(process.waitFor() == 0 && output.isNotEmpty()) {
        "Unable to determine the release source revision"
    }
    return output
}

fun gitWorkingTreeState(): String {
    val process =
        ProcessBuilder("git", "status", "--porcelain=v1", "--untracked-files=all")
            .directory(projectDir)
            .redirectErrorStream(true)
            .start()
    val output = process.inputStream.bufferedReader().use { it.readText() }
    val exitCode = process.waitFor()
    check(exitCode == 0) { "Unable to determine whether the release source tree is clean: $output" }
    return if (output.isBlank()) "clean" else "dirty"
}

dependencies {
    errorprone("com.google.errorprone:error_prone_core:2.49.0")

    implementation("org.bouncycastle:bcprov-jdk18on:1.84")
    implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-cbor:2.22.0")

    testImplementation(platform("org.junit:junit-bom:5.14.3"))
    testImplementation("org.hamcrest:hamcrest:2.2")
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("org.testfx:testfx-junit5:4.0.18")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

dependencyLocking {
    lockAllConfigurations()
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    options.release = 21
    options.compilerArgs.addAll(listOf("-Xlint:all", "-Werror"))
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}

tasks.withType<SpotBugsTask>().configureEach {
    effort = Effort.MAX
    reportLevel = Confidence.MEDIUM
    reports.create("html") {
        required = true
    }
    reports.create("xml") {
        required = false
    }
}

spotless {
    java {
        googleJavaFormat("1.28.0")
        formatAnnotations()
        removeUnusedImports()
        trimTrailingWhitespace()
        endWithNewline()
    }
    kotlinGradle {
        ktlint("1.7.1")
        trimTrailingWhitespace()
        endWithNewline()
    }
    format("misc") {
        // Private root notes are intentionally ignored and must not influence the public build.
        target("README.md", ".gitignore", ".gitattributes", "*.properties")
        trimTrailingWhitespace()
        endWithNewline()
    }
}

tasks.named("check") {
    dependsOn("spotlessCheck")
}

tasks.register<VerifyReleaseToolchainTask>("verifyReleaseToolchain") {
    group = "release"
    description = "Verifies the pinned Java and Gradle Wrapper release toolchain."
    expectedJavaMajor.set("21")
    wrapperProperties.set(layout.projectDirectory.file("gradle/wrapper/gradle-wrapper.properties"))
}

tasks.register<VerifyReleaseDependenciesTask>("verifyReleaseDependencies") {
    group = "release"
    description = "Verifies exact runtime dependencies, dependency locks, and licence evidence."
    dependsOn("verifyReleaseToolchain")
    requiredCoordinates.set(releaseRuntimeDependencies)
    buildScript.set(layout.projectDirectory.file("build.gradle.kts"))
    dependencyLock.set(layout.projectDirectory.file("gradle.lockfile"))
    settingsDependencyLock.set(layout.projectDirectory.file("settings-gradle.lockfile"))
    licenseReview.set(layout.projectDirectory.file("docs/release/dependency-licenses.md"))
    packageContent.set(layout.projectDirectory.dir("release/package-content"))
    runtimeClasspath.from(configurations.runtimeClasspath)
}

tasks.register("releaseVerification") {
    group = "release"
    description = "Runs the local release checks that do not require external signing or CVE feeds."
    dependsOn("spotlessCheck", "test", "spotbugsMain", "spotbugsTest", "verifyReleaseDependencies")
}

val releasePackageVersion = providers.gradleProperty("releaseVersion").orElse("0.1.0")
val javaHome = File(System.getProperty("java.home"))
val runtimeImageDirectory = layout.buildDirectory.dir("release/runtime-image")
val appImageDirectory = layout.buildDirectory.dir("release/app-image")
val releaseJar = tasks.named<org.gradle.jvm.tasks.Jar>("jar").flatMap { it.archiveFile }
val runtimeClasspath = configurations.runtimeClasspath.get()
val staticPackageContentDirectory = layout.projectDirectory.dir("release/package-content")
val preparedPackageContentDirectory = layout.buildDirectory.dir("release/package-content")
val releaseHostOs = releaseHostOsName()
val releaseHostArchitecture = releaseHostArchitectureName()
val releaseArchiveDirectory = layout.buildDirectory.dir("release/archives/$releaseHostOs")

tasks.register("prepareReleasePackageContent") {
    group = "release"
    description = "Stages package content with exact legal files from resolved runtime artifacts."
    dependsOn("verifyReleaseDependencies")
    inputs.dir(staticPackageContentDirectory)
    inputs.files(runtimeClasspath)
    outputs.dir(preparedPackageContentDirectory)
    doLast {
        val destination = preparedPackageContentDirectory.get().asFile
        destination.deleteRecursively()
        copy {
            from(staticPackageContentDirectory)
            into(destination)
        }
        val licenseDirectory = File(destination, "licenses").apply { mkdirs() }
        val runtimeJars = runtimeClasspath.files.filter { it.extension == "jar" }.sortedBy { it.name }
        val extractedFiles = mutableListOf<String>()
        runtimeJars.forEach { artifact ->
            ZipFile(artifact).use { archive ->
                archive
                    .entries()
                    .asSequence()
                    .filter { entry ->
                        !entry.isDirectory &&
                            entry.name.startsWith("META-INF/") &&
                            Regex("(?i)(license|notice)").containsMatchIn(entry.name.substringAfterLast('/'))
                    }.sortedBy { it.name }
                    .forEach { entry ->
                        val legalName =
                            "${artifact.name.removeSuffix(".jar")}-${entry.name.substringAfterLast('/')}"
                        check(legalName.matches(Regex("[A-Za-z0-9._-]+"))) {
                            "Unexpected legal-file name in ${artifact.name}: ${entry.name}"
                        }
                        val output = File(licenseDirectory, legalName)
                        archive.getInputStream(entry).use { input ->
                            output.outputStream().use { outputStream -> input.copyTo(outputStream) }
                        }
                        extractedFiles += "licenses/$legalName"
                    }
            }
        }
        val notice = File(destination, "THIRD-PARTY-NOTICES.txt")
        notice.writeText(
            buildString {
                appendLine("VultBridge third-party notices")
                appendLine("==============================")
                appendLine()
                appendLine(
                    "This notice accompanies the exact runtime artifacts resolved by the pinned " +
                        "Gradle lockfile. The complete applicable license and notice texts are " +
                        "included under licenses/.",
                )
                appendLine()
                appendLine("Resolved runtime artifacts")
                appendLine("--------------------------")
                runtimeJars.forEach { appendLine(it.name) }
                appendLine()
                appendLine("Static license texts")
                appendLine("--------------------")
                listOf(
                    "licenses/OpenJFX-GPLv2-with-Classpath-Exception.txt",
                    "licenses/Bouncy-Castle-License.txt",
                ).forEach(::appendLine)
                appendLine()
                appendLine("License and notice files copied byte-for-byte from runtime JARs")
                appendLine("---------------------------------------------------------------")
                extractedFiles.sorted().forEach(::appendLine)
                appendLine()
                appendLine(
                    "The bundled Java runtime retains its own legal files under legal/. " +
                        "Build-time tools and test-only dependencies are not included in the " +
                        "application runtime image.",
                )
            },
        )
    }
}

tasks.register("releaseRuntimeImage") {
    group = "release"
    description = "Builds the minimal jlink runtime image for the current host platform."
    notCompatibleWithConfigurationCache("Invokes the host JDK jlink process")
    dependsOn(tasks.named("jar"), "verifyReleaseToolchain", "verifyReleaseDependencies")
    inputs.file(releaseJar)
    inputs.files(runtimeClasspath)
    outputs.dir(runtimeImageDirectory)
    doLast {
        val destination = runtimeImageDirectory.get().asFile
        destination.deleteRecursively()
        val modulePath =
            (runtimeClasspath.files + releaseJar.get().asFile)
                .joinToString(File.pathSeparator) { it.absolutePath }
        runCommand(
            listOf(
                File(javaHome, "bin/jlink").absolutePath,
                "--module-path",
                modulePath,
                "--add-modules",
                "com.vultbridge",
                "--strip-debug",
                "--no-header-files",
                "--no-man-pages",
                "--compress=2",
                "--ignore-signing-information",
                "--output",
                destination.absolutePath,
            ),
        )
        check(File(destination, "bin/java").isFile) { "jlink did not create a runnable image" }
    }
}

tasks.register("releaseAppImage") {
    group = "release"
    description = "Builds a native jpackage app-image for the current host platform."
    notCompatibleWithConfigurationCache("Invokes the host JDK jpackage process")
    dependsOn(tasks.named("releaseRuntimeImage"), tasks.named("prepareReleasePackageContent"))
    inputs.property("releaseVersion", releasePackageVersion)
    inputs.dir(preparedPackageContentDirectory)
    inputs.dir(runtimeImageDirectory)
    outputs.dir(appImageDirectory)
    doLast {
        val destination = appImageDirectory.get().asFile
        destination.deleteRecursively()
        destination.mkdirs()
        runCommand(
            listOf(
                File(javaHome, "bin/jpackage").absolutePath,
                "--type",
                "app-image",
                "--name",
                "VultBridge",
                "--app-version",
                releasePackageVersion.get(),
                "--vendor",
                "VultBridge",
                "--description",
                "Local authenticated encrypted vault",
                "--runtime-image",
                runtimeImageDirectory.get().asFile.absolutePath,
                "--app-content",
                preparedPackageContentDirectory.get().asFile.absolutePath,
                "--module",
                "com.vultbridge/com.vultbridge.app.VultBridgeApplication",
                "--dest",
                destination.absolutePath,
            ),
        )
        check(
            Files.walk(destination.toPath()).use { paths ->
                paths.anyMatch { path -> path.fileName.toString() == "VultBridge" }
            },
        ) {
            "jpackage did not create the VultBridge launcher"
        }
    }
}

tasks.register("releaseManifest") {
    group = "release"
    description = "Writes one canonical SHA-256 manifest for the current-host release archives."
    notCompatibleWithConfigurationCache("Scans and hashes the generated package")
    dependsOn("releaseArchives")
    inputs.property("releaseVersion", releasePackageVersion)
    inputs.dir(releaseArchiveDirectory)
    outputs.file(releaseArchiveDirectory.map { it.file("release-manifest.txt") })
    doLast {
        check(releaseHostOs != "unsupported") {
            "Release packaging supports macOS and Linux only; found ${System.getProperty("os.name")}"
        }
        check(releaseHostArchitecture != "unsupported") {
            "Unsupported release architecture: ${System.getProperty("os.arch")}"
        }
        val artifactRoot = releaseArchiveDirectory.get().asFile.toPath()
        val expectedNames = releaseArchiveNames(releaseHostOs, releaseHostArchitecture)
        val entries =
            expectedNames.map { name ->
                val archive = artifactRoot.resolve(name)
                check(Files.isRegularFile(archive, LinkOption.NOFOLLOW_LINKS)) {
                    "Required release archive is missing: $name"
                }
                Triple(name, sha256File(archive), Files.size(archive))
            }
        val unexpected =
            Files.list(artifactRoot).use { paths ->
                paths
                    .filter { path ->
                        path.fileName.toString() != "release-manifest.txt" &&
                            (
                                !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) ||
                                    path.fileName.toString() !in expectedNames
                            )
                    }.map { it.fileName.toString() }
                    .toList()
            }
        check(unexpected.isEmpty()) { "Unexpected files in release archive directory: $unexpected" }
        val manifest =
            buildString {
                append("VULTBRIDGE-RELEASE-MANIFEST\t2\n")
                append("name\tVultBridge\n")
                append("version\t")
                append(releasePackageVersion.get())
                append("\nos\t")
                append(releaseHostOs)
                append("\narchitecture\t")
                append(releaseHostArchitecture)
                append("\nsourceRevision\t")
                append(gitOutput(listOf("rev-parse", "HEAD")))
                append("\nsourceTreeState\t")
                append(gitWorkingTreeState())
                append("\nsignatureStatus\t")
                append(if (releaseHostOs == "macos") "unsigned-ad-hoc" else "hashes-only")
                append('\n')
                append("files\n")
                entries.forEach { entry ->
                    check(
                        entry.first.isNotEmpty() &&
                            !entry.first.contains('\t') &&
                            !entry.first.contains('\n') &&
                            !entry.first.startsWith('/'),
                    ) {
                        "Release manifest path is not canonical: ${entry.first}"
                    }
                    append(entry.second)
                    append('\t')
                    append(entry.third)
                    append('\t')
                    append(entry.first)
                    append('\n')
                }
            }
        releaseArchiveDirectory.get().file("release-manifest.txt").asFile.apply {
            parentFile.mkdirs()
            writeText(manifest)
        }
    }
}

tasks.register("verifyReleasePackage") {
    group = "release"
    description = "Checks the application image for a launcher and forbidden development content."
    notCompatibleWithConfigurationCache("Scans the generated package")
    dependsOn(tasks.named("releaseAppImage"))
    inputs.dir(appImageDirectory)
    doLast {
        val root = appImageDirectory.get().asFile.toPath()
        val forbidden = listOf(".vltb", "test_files", "AGENTS.md", "memory", ".git", "build.gradle")
        var fileCount = 0
        var launcherFound = false
        var noticeFound = false
        Files.walk(root).use { paths ->
            paths.forEach { path ->
                val relative = root.relativize(path).toString().replace(File.separatorChar, '/')
                check(!Files.isSymbolicLink(path)) { "Release package contains a symbolic link: $relative" }
                check(forbidden.none { token -> relative.contains(token, ignoreCase = true) }) {
                    "Release package contains forbidden content: $relative"
                }
                if (Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
                    fileCount++
                    if (path.fileName.toString() == "VultBridge") launcherFound = true
                    if (path.fileName.toString() == "THIRD-PARTY-NOTICES.txt") noticeFound = true
                }
            }
        }
        check(fileCount > 0) { "Release package contains no regular files" }
        check(launcherFound) { "Release package contains no VultBridge launcher" }
        check(noticeFound) { "Release package contains no third-party notice" }
        val requiredLicenseNames =
            listOf(
                "OpenJFX-GPLv2-with-Classpath-Exception.txt",
                "Bouncy-Castle-License.txt",
                "jackson-core-2.22.0-LICENSE",
                "jackson-core-2.22.0-NOTICE",
                "jackson-dataformat-cbor-2.22.0-LICENSE",
                "jackson-dataformat-cbor-2.22.0-NOTICE",
            )
        requiredLicenseNames.forEach { licenseName ->
            check(
                Files.walk(root).use { paths ->
                    paths.anyMatch { path ->
                        Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) &&
                            path.fileName.toString().startsWith(licenseName)
                    }
                },
            ) {
                "Release package is missing exact legal text: $licenseName"
            }
        }
    }
}

tasks.register("releasePackage") {
    group = "release"
    description = "Builds and inventories the current-host final release archives."
    dependsOn("releaseVerification", "releaseManifest", "verifyReleasePackage")
}

tasks.register("releaseArchives") {
    group = "release"
    description = "Creates the versionless current-host release archives."
    notCompatibleWithConfigurationCache("Invokes host-native archive tools")
    dependsOn(tasks.named("releaseAppImage"), tasks.named("verifyReleasePackage"))
    inputs.property("releaseVersion", releasePackageVersion)
    inputs.dir(appImageDirectory)
    outputs.dir(releaseArchiveDirectory)
    doLast {
        check(releaseHostOs != "unsupported") {
            "Release packaging supports macOS and Linux only; found ${System.getProperty("os.name")}"
        }
        check(releaseHostArchitecture != "unsupported") {
            "Unsupported release architecture: ${System.getProperty("os.arch")}"
        }
        val outputDirectory = releaseArchiveDirectory.get().asFile
        outputDirectory.mkdirs()
        val archiveNames = releaseArchiveNames(releaseHostOs, releaseHostArchitecture)
        archiveNames
            .map { File(outputDirectory, it) }
            .forEach { existing ->
                if (existing.exists()) check(existing.delete()) { "Unable to replace $existing" }
            }
        val appImageRoot = appImageDirectory.get().asFile
        when (releaseHostOs) {
            "macos" -> {
                val appBundle = File(appImageRoot, "VultBridge.app")
                check(appBundle.isDirectory) { "The macOS app bundle is missing: $appBundle" }
                runCommand(
                    listOf(
                        "/usr/bin/ditto",
                        "-c",
                        "-k",
                        "--sequesterRsrc",
                        "--keepParent",
                        appBundle.absolutePath,
                        File(outputDirectory, archiveNames[0]).absolutePath,
                    ),
                )
                runCommand(
                    listOf(
                        "/usr/bin/hdiutil",
                        "create",
                        "-volname",
                        "VultBridge",
                        "-srcfolder",
                        appBundle.absolutePath,
                        "-ov",
                        "-format",
                        "UDZO",
                        File(outputDirectory, archiveNames[1]).absolutePath,
                    ),
                )
            }
            "linux" -> {
                val applicationDirectory = File(appImageRoot, "VultBridge")
                check(applicationDirectory.isDirectory) {
                    "The Linux app image directory is missing: $applicationDirectory"
                }
                runCommand(
                    listOf(
                        "/usr/bin/tar",
                        "-czf",
                        File(outputDirectory, archiveNames.single()).absolutePath,
                        "-C",
                        appImageRoot.absolutePath,
                        "VultBridge",
                    ),
                )
            }
        }
        archiveNames.forEach { name ->
            val archive = File(outputDirectory, name)
            check(archive.isFile && archive.length() > 0) {
                "The release archive was not created: $archive"
            }
        }
    }
}

fun sha256File(path: Path): String {
    val digest = MessageDigest.getInstance("SHA-256")
    Files.newInputStream(path).use { input ->
        val buffer = ByteArray(1024 * 1024)
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            digest.update(buffer, 0, read)
        }
    }
    return digest.digest().joinToString("") { byte -> "%02x".format(byte) }
}
