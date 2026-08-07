import ch.ubique.uniffi.plugin.extensions.useRustUpLinker

plugins {
	alias(libs.plugins.kotlin.multiplatform)
	alias(libs.plugins.android.kotlin.multiplatform.library)
	alias(libs.plugins.skie)
	alias(libs.plugins.vanniktech.publish)
	alias(libs.plugins.kotlin.serialization)
	alias(libs.plugins.uniffi.plugin)
}

kotlin {
	compilerOptions {
		freeCompilerArgs.add("-Xexpect-actual-classes")
		freeCompilerArgs.add("-Xwhen-guards")
	}

	jvmToolchain(17)

	android {
		namespace = "org.kapunsdk.credentials"
		compileSdk = libs.versions.android.compileSdk.get().toInt()
		minSdk = libs.versions.android.minSdk.get().toInt()

		withHostTest {}

		optimization {
			consumerKeepRules.publish = true
			consumerKeepRules.file(rootProject.file("consumer-jna-rules.pro"))
		}
	}
	jvm()
	listOf(

		iosArm64(),
		iosSimulatorArm64()
	).forEach { iosTarget ->
		iosTarget.binaries.framework {
			baseName = "kapun-credentials"
			isStatic = true
		}

		iosTarget.binaries.all {
		}

		iosTarget.compilations.configureEach {
			useRustUpLinker()
		}
	}

	sourceSets {
		commonMain.dependencies {
			implementation(project(":kapun-util"))
			implementation(project(":kapun-crypto"))
			implementation(project(":kapun-proximity"))
			implementation(libs.kotlin.coroutines)
			implementation(libs.koin.core)
			implementation(libs.kotlin.serialization)
			implementation(libs.ktor.client.cio)
			implementation(libs.ktor.serialization.json)
			implementation(libs.ktor.client.content.negotiation)
		}

		commonTest.dependencies {
			implementation(libs.kotlin.test)
		}

		androidMain.dependencies {
			implementation(libs.koin.android)
			implementation("net.java.dev.jna:jna:5.18.1@aar") // Android-compatible
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
}

cargo {
	packageDirectory = layout.projectDirectory.dir("rust")
	ndkVersion = libs.versions.android.ndk.get()
}

mavenPublishing {
	coordinates(artifactId= property("ARTIFACT_ID").toString(), version= project.version.toString())
	publishToMavenCentral(true)
	signAllPublications()
}
