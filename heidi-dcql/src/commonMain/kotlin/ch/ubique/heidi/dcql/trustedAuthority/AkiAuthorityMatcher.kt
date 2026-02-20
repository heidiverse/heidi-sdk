package ch.ubique.heidi.dcql.trustedAuthority

import uniffi.heidi_crypto_rust.getX509FromJwt
import uniffi.heidi_dcql_rust.Credential
import uniffi.heidi_dcql_rust.TrustedAuthority
import uniffi.heidi_dcql_rust.TrustedAuthorityMatcher
import uniffi.heidi_dcql_rust.TrustedAuthorityQueryType
import uniffi.heidi_dcql_rust.registerMatcher

class AkiAuthorityMatcher : TrustedAuthorityMatcher {
	init {
		registerMatcher(this)
	}

	override fun id(): String = "AkiSdJwtAuthorityMatcher"

	override fun matches(
		value: Credential,
		trustedAuthority: TrustedAuthority,
	): Boolean? {
		if(value !is Credential.SdJwtCredential) {
			return null
		}
		val x509Chain = getX509FromJwt(value.v1.originalJwt) ?: return null
		for(c in x509Chain) {
			if(trustedAuthority.values.contains(c.authorityKeyIdentifier)) {
				return true
			}
		}
		return false
	}

	override fun queryType(): TrustedAuthorityQueryType = TrustedAuthorityQueryType.AUTHORITY_KEY_IDENTIFIER
}