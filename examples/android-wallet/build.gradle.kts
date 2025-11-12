plugins {
	alias(libs.plugins.android.application)
	alias(libs.plugins.kotlin.android)
	alias(libs.plugins.kotlin.parcelize)
	alias(libs.plugins.compose.compiler)
}

android {
	namespace = "ch.ubique.heidi.sample.wallet"
	compileSdk = libs.versions.android.compileSdk.get().toInt()

	ndkVersion = libs.versions.android.ndk.get()

	defaultConfig {
		applicationId = "ch.ubique.heidi.sample.wallet"
		minSdk = libs.versions.android.minSdk.get().toInt()
		targetSdk = libs.versions.android.targetSdk.get().toInt()
		versionCode = 1
		versionName = "1.0.0"

		testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
	}
	flavorDimensions += "version"

	buildTypes {
		release {
			isMinifyEnabled = false
			proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
		}
	}

	compileOptions {
		sourceCompatibility = JavaVersion.VERSION_17
		targetCompatibility = JavaVersion.VERSION_17
	}

	kotlinOptions {
		jvmTarget = "17"
	}

	buildFeatures {
		compose = true
		viewBinding = true
	}

	packaging {
		resources {
			excludes += listOf(
//				"/META-INF/{AL2.0,LGPL2.1}",
//				"META-INF/DEPENDENCIES",
//				"META-INF/INDEX.LIST",
				"META-INF/versions/9/OSGI-INF/MANIFEST.MF",
			)
		}
	}
}

dependencies {
	implementation(project(":heidi-wallet"))
	implementation(project(":heidi-proximity"))
	implementation(project(":heidi-crypto"))

	implementation(libs.androidx.coreKtx)
	implementation(libs.androidx.appcompat)
	implementation(libs.androidx.lifecycle.runtimeKtx)
	implementation(libs.androidx.activity.compose)

	implementation(libs.kotlin.serialization)
	implementation(libs.kotlin.coroutines)
	implementation(libs.koin.android)

	implementation(platform(libs.compose.bom))
	implementation(libs.compose.ui)
	implementation(libs.compose.ui.graphics)
	implementation(libs.compose.ui.tooling.preview)
	implementation(libs.compose.material3)
	debugImplementation(libs.compose.ui.tooling)
	debugImplementation(libs.compose.ui.test.manifest)

	implementation(libs.accompanist.permissions)

	implementation(libs.ubique.qrscanner.zxing)
	implementation(libs.ubique.qrscanner.compose)
}