package ch.ubique.heidi.dcql.trustedAuthority

import ch.ubique.heidi.util.extensions.get
import uniffi.heidi_dcql_rust.Credential
import uniffi.heidi_dcql_rust.TrustedAuthority
import uniffi.heidi_dcql_rust.TrustedAuthorityMatcher
import uniffi.heidi_dcql_rust.TrustedAuthorityQueryType
import uniffi.heidi_dcql_rust.registerMatcher

class DidAuthorityMatcher : TrustedAuthorityMatcher {
	override fun id(): String = "DidAuthorityMatcher"

	override fun matches(value: Credential, trustedAuthority: TrustedAuthority): Boolean? {
		return when (value) {
			is Credential.SdJwtCredential -> {
				val issuer = value.v1.claims["iss"]
				null
			}
			else -> null
		}
	}

	override fun queryType(): TrustedAuthorityQueryType = TrustedAuthorityQueryType.DecentralizedIdentifier

	companion object {
		fun load() {
			registerMatcher(DidAuthorityMatcher())
		}
	}
}