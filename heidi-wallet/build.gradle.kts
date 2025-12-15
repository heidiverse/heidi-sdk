import ch.ubique.uniffi.plugin.extensions.useRustUpLinker

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.kotlin.atomicfu)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.compose.multiplatform)
    alias(libs.plugins.compose.compiler)
    alias(libs.plugins.sqldelight)
    alias(libs.plugins.android.library)
    alias(libs.plugins.skie)
    alias(libs.plugins.uniffi.plugin)
    alias(libs.plugins.vanniktech.publish)
}

kotlin {
    compilerOptions {
        freeCompilerArgs.add("-Xexpect-actual-classes")
        freeCompilerArgs.add("-Xwhen-guards")
    }

	sourceSets.all {
		languageSettings {
			optIn("kotlin.time.ExperimentalTime")
		}
	}

	jvmToolchain(17)

    androidTarget {
        publishLibraryVariants = listOf("release")
    }

    jvm()

    listOf(
        iosX64(),
        iosArm64(),
        iosSimulatorArm64()
    ).forEach { iosTarget ->
        iosTarget.binaries.framework {
            baseName = "heidi-wallet"
            isStatic = true

            export(projects.heidiUtil)
            export(projects.heidiCredentials)
            export(projects.heidiIssuance)
            export(projects.heidiPresentation)
            export(projects.heidiTrust)
            export(projects.heidiProximity)
            export(projects.heidiVisualization)
        }

        iosTarget.binaries.all {
            freeCompilerArgs += "-Xallocator=mimalloc"
        }

        iosTarget.compilations.getByName("main") {
            useRustUpLinker()
        }
    }

    sourceSets {
        all {
            languageSettings.optIn("kotlin.uuid.ExperimentalUuidApi")
        }

        commonMain.dependencies {
            api(project(":heidi-util"))
            api(project(":heidi-credentials"))
            api(project(":heidi-dcql"))
            implementation(project(":heidi-crypto"))
            api(project(":heidi-issuance"))
            api(project(":heidi-presentation"))
            api(project(":heidi-trust"))
            api(project(":heidi-proximity"))
            api(project(":heidi-visualization"))

            implementation(libs.kotlin.coroutines)
            implementation(libs.kotlin.datetime)
            implementation(libs.kotlin.serialization)

            implementation(libs.koin.core)

            implementation(libs.skie)
            implementation(libs.sqldelight.coroutines)
            implementation(libs.ktor.client.cio)
            implementation(libs.ktor.serialization.json)
            implementation(libs.ktor.client.content.negotiation)

            implementation(libs.owf.identity)

            // Compose Resources (currently only used for tests, but doesn't work in commonTest)
            implementation(compose.runtime)
            implementation(compose.components.resources)
        }

        commonTest.dependencies {
            implementation(libs.kotlin.test)
        }

        androidMain.dependencies {
            implementation(libs.koin.android)
            implementation(libs.sqldelight.android)
        }

        iosMain.dependencies {
            implementation(libs.sqldelight.native)
            implementation(libs.ktor.client.darwin)
        }
    }
}

android {
    namespace = "ch.ubique.heidi.wallet"
    compileSdk = libs.versions.android.compileSdk.get().toInt()

    ndkVersion = libs.versions.android.ndk.get()

    defaultConfig {
        minSdk = libs.versions.android.minSdk.get().toInt()
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

sqldelight {
    databases {
        create("HeidiDatabase") {
            packageName.set("ch.ubique.heidi.wallet")
        }
    }
}

skie {
    analytics {
        enabled = false
        disableUpload = true
    }
}

uniffi {
    bindgenFromGitTag(
        "https://github.com/UbiqueInnovation/uniffi-kotlin-multiplatform-bindings.git",
        libs.versions.uniffi.bindgen.get()
    )
    generateFromLibrary()
//    generateFromLibrary {
//        config.set(project.projectDir.resolve("uniffi.toml"))
//    }
}

cargo {
    packageDirectory = layout.projectDirectory.dir("rust")
//    builds.android {
//        variants.forEach {
//            if(it.rustTarget == RustAndroidTarget.Arm64) {
//                debug.profile = CargoProfile.Dev
//            } else {
//                debug.profile = CargoProfile.Release
//            }
//        }
//    }
//    builds.desktop {
//        debug.profile = CargoProfile.Release
//    }
//    builds.appleMobile {
//        debug.profile = CargoProfile.Release
//    }

//    builds.jvm {
//        // Build JVM only for the current host platform
//        jvm = (rustTarget == RustHost.current.rustTarget)
//    }
}

compose.resources {
    publicResClass = false
    packageOfResClass = "ch.ubique.heidi.wallet"
    generateResClass = always
}

mavenPublishing {
    coordinates(artifactId= property("ARTIFACT_ID").toString(), version= project.version.toString())
    publishToMavenCentral(true)
    signAllPublications()
}