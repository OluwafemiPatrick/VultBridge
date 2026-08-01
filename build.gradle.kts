import com.github.spotbugs.snom.Confidence
import com.github.spotbugs.snom.Effort
import com.github.spotbugs.snom.SpotBugsTask

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
