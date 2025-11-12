plugins {
	// Kotlin & KMP plugins
	alias(libs.plugins.kotlin.multiplatform) apply false
	alias(libs.plugins.kotlin.parcelize) apply false
	alias(libs.plugins.kotlin.serialization) apply false
	alias(libs.plugins.kotlin.atomicfu) apply false
	alias(libs.plugins.compose.multiplatform) apply false
	alias(libs.plugins.sqldelight) apply false
	alias(libs.plugins.jetbrains.kotlin.jvm) apply false

	// Android specific plugins
	alias(libs.plugins.android.library) apply false
	alias(libs.plugins.android.application) apply false
	alias(libs.plugins.kotlin.android) apply false
	alias(libs.plugins.compose.compiler) apply false
	alias(libs.plugins.ksp) apply false
	alias(libs.plugins.ktorfit) apply false

	// iOS specific plugins
	alias(libs.plugins.skie) apply false

	// Ubique plugins
	alias(libs.plugins.ubique.alpaka) apply false
	alias(libs.plugins.ubique.preset) apply false
	alias(libs.plugins.ubique.signing) apply false

	// Rust plugins
	alias(libs.plugins.uniffi.plugin) apply false

	// Library publishing plugins
	alias(libs.plugins.vanniktech.publish) apply false
}

allprojects {
	group = "ch.heidi-universe"
	version = getProjectVersion()
}

private fun getProjectVersion(): String {
	val versionFromGradleProperties = runCatching { property("ARTIFACT_VERSION").toString() }.getOrNull()
	val versionFromWorkflow = runCatching { property("githubRefName").toString().removePrefix("v") }.getOrNull()
	return versionFromWorkflow ?: versionFromGradleProperties ?: "untagged"
}