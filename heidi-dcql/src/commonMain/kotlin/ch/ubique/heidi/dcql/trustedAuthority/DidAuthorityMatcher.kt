package ch.ubique.heidi.dcql.trustedAuthority

import ch.ubique.heidi.util.extensions.asString
import ch.ubique.heidi.util.extensions.get
import uniffi.heidi_crypto_rust.getKidFromJwt
import uniffi.heidi_dcql_rust.Credential
import uniffi.heidi_dcql_rust.TrustedAuthority
import uniffi.heidi_dcql_rust.TrustedAuthorityMatcher
import uniffi.heidi_dcql_rust.TrustedAuthorityQueryType
import uniffi.heidi_dcql_rust.registerMatcher

object DidAuthorityMatcher : TrustedAuthorityMatcher {
	fun register() {
		registerMatcher(this)
	}

	override fun id(): String = "DidSdJwtAuthorityMatcher"

	override fun matches(value: Credential, trustedAuthority: TrustedAuthority): Boolean? {
		return when (value) {
			is Credential.SdJwtCredential -> {
				val kid = getKidFromJwt(value.v1.originalJwt)
				val did = kid?.split("#")?.firstOrNull()
				val issuer = value.v1.claims["iss"].asString() ?: did ?: return false
				trustedAuthority.values.contains(issuer)
			}
			else -> null
		}
	}

	override fun queryType(): TrustedAuthorityQueryType = TrustedAuthorityQueryType.DECENTRALIZED_IDENTIFIER
}