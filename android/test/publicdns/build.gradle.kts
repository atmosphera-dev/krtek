plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.mullvad.unit.test)
}

android {
    namespace = "net.mullvad.mullvadvpn.test.publicdns"
    compileSdk = libs.versions.compile.sdk.major.get().toInt()
    compileSdkMinor = libs.versions.compile.sdk.minor.get().toInt()
    buildToolsVersion = libs.versions.build.tools.get()

    defaultConfig {
        applicationId = "net.mullvad.mullvadvpn.test.publicdns"
        minSdk = libs.versions.min.sdk.get().toInt()
        targetSdk = libs.versions.target.sdk.get().toInt()
        versionCode = 1
        versionName = "1"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        testInstrumentationRunnerArguments["runnerBuilder"] =
            "de.mannodermaus.junit5.AndroidJUnit5Builder"
    }

    sourceSets { getByName("main").java.directories += "src/shared/java" }

    lint {
        lintConfig = file("${rootProject.projectDir}/config/lint.xml")
        abortOnError = true
        warningsAsErrors = true
    }
}

tasks.withType<Test>().configureEach {
    val scratch =
        System.getenv("TMPDIR")?.let(::File)
            ?: layout.buildDirectory.dir("tmp/unit-tests").get().asFile
    systemProperty("java.io.tmpdir", scratch.absolutePath)
    doFirst { check(scratch.isDirectory || scratch.mkdirs()) }
}

dependencies {
    androidTestImplementation(libs.androidx.test.core)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.junit.jupiter.api)
    androidTestImplementation(libs.junit5.android.test.extensions)
    androidTestRuntimeOnly(libs.junit5.android.test.runner)
}
