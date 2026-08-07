package org.kapunsdk.trustedAuthority

import uniffi.kapun_crypto_rust.getX509FromJwt
import uniffi.kapun_dcql_rust.Credential
import uniffi.kapun_dcql_rust.TrustedAuthority
import uniffi.kapun_dcql_rust.TrustedAuthorityMatcher
import uniffi.kapun_dcql_rust.TrustedAuthorityQueryType
import uniffi.kapun_dcql_rust.registerMatcher
import kotlin.text.iterator

object AkiAuthorityMatcher : TrustedAuthorityMatcher {
	fun register() {
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