package ch.ubique.heidi.trust.did.models

data class VersionId(
    val version: Int,
    val entryHash: String,
) {
    override fun toString(): String =
        "$version-$entryHash"
}