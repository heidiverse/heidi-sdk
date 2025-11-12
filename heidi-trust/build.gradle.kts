import ch.ubique.uniffi.plugin.extensions.useRustUpLinker

plugins {
	alias(libs.plugins.kotlin.multiplatform)
	alias(libs.plugins.kotlin.serialization)
	alias(libs.plugins.kotlin.atomicfu)
	alias(libs.plugins.android.library)
	alias(libs.plugins.skie)
	alias(libs.plugins.vanniktech.publish)
	alias(libs.plugins.uniffi.plugin)
}

kotlin {
	compilerOptions {
		freeCompilerArgs.add("-Xexpect-actual-classes")
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
			baseName = "heidi-trust"
			isStatic = true
		}

		iosTarget.binaries.all {
			freeCompilerArgs += "-Xallocator=mimalloc"
		}

		iosTarget.compilations.getByName("main") {
			useRustUpLinker()
		}
	}

	sourceSets {
		commonMain.dependencies {
			implementation(project(":heidi-util"))
			implementation(project(":heidi-crypto"))
			implementation(project(":heidi-credentials"))
			implementation(project(":heidi-issuance"))
			implementation(project(":heidi-presentation"))
			implementation(project(":heidi-dcql"))

			implementation(libs.kotlin.coroutines)
			implementation(libs.kotlin.serialization)

			implementation(libs.koin.core)

			implementation(libs.ktor.client.cio)
			implementation(libs.ktor.client.content.negotiation)
			implementation(libs.ktor.serialization.json)
			implementation(libs.kotlin.datetime)
		}

		commonTest.dependencies {
			implementation(libs.kotlin.test)
			implementation(libs.kotlin.coroutines.test)
		}

		androidMain.dependencies {
			implementation(libs.koin.android)
		}

		iosMain.dependencies {
			implementation(libs.ktor.client.darwin)
		}
	}
}

android {
	namespace = "ch.ubique.heidi.trust"
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
}

mavenPublishing {
	coordinates(project.group.toString(), property("ARTIFACT_ID").toString(), project.version.toString())
	publishToMavenCentral(true)
	signAllPublications()
}