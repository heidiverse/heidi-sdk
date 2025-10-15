package ch.ubique.heidi.trust.framework.oidcfederation

import ch.ubique.heidi.credentials.models.credential.CredentialModel
import ch.ubique.heidi.issuance.metadata.data.CredentialIssuerMetadata
import ch.ubique.heidi.presentation.request.PresentationRequest
import ch.ubique.heidi.trust.framework.DocumentProvider
import ch.ubique.heidi.trust.framework.JWKTrustAnchorProvider
import ch.ubique.heidi.trust.framework.TrustFramework
import ch.ubique.heidi.trust.framework.ValidationInfo
import ch.ubique.heidi.trust.model.AgentInformation
import ch.ubique.heidi.trust.model.AgentType
import uniffi.heidi_trust_rust.FederationException
import uniffi.heidi_trust_rust.oidcfTrustChainFromPresentationRequest
import uniffi.heidi_trust_rust.oidcfTrustChainFromUrl

const val OIDC_FEDERATION_TRUST_FRAMEWORK_ID: String = "oidc_federation_framework"

class OidcFederationTrustFramerwork(
	val documentProvider: DocumentProvider? = null,
	val jwkTrustAnchorProvider: JWKTrustAnchorProvider = StaticJWKTrustAnchorProvider(),
) : TrustFramework {
	override val frameworkId: String
		get() = OIDC_FEDERATION_TRUST_FRAMEWORK_ID


	override suspend fun getIssuerInformation(
		baseUrl: String,
		credentialConfigurationIds: List<String>,
		credentialIssuerMetadata: CredentialIssuerMetadata
	): AgentInformation? {
		// TODO: get credentialIssuerMetadata from here instead of fetching it earlier.
		val trustInfo = try {
			oidcfTrustChainFromUrl(credentialIssuerMetadata.credentialIssuer);
		} catch (e: FederationException.FetchingFailed) {
			return null
		}

		val isTrusted = trustInfo.trustAnchorKeys.any {
			jwkTrustAnchorProvider.isTrusted(it)
		};
		val isVerified = credentialConfigurationIds.all {
			trustInfo.leaf.credentialConfigurationsSupported?.contains(it) ?: false
		};

		return AgentInformation(
			type = AgentType.ISSUER,
			domain = trustInfo.leaf.domain,
			displayName = trustInfo.leaf.displayName,
			trustFrameworkId = OIDC_FEDERATION_TRUST_FRAMEWORK_ID,
			logoUri = trustInfo.leaf.logoUri,
			isTrusted = isTrusted,
			isVerified = isVerified,
			identityTrust = null,
			issuanceTrust = trustInfo.subordinateStatements.joinToString(separator = "\n"),
			verificationTrust = null,
		)
	}

	override suspend fun getVerifierInformation(
		requestUri: String, presentationRequest: PresentationRequest, originalRequest: String?
	): AgentInformation? {
		if (originalRequest == null) {
			return null
		}
		val trustInfo = try {
			oidcfTrustChainFromPresentationRequest(originalRequest!!);
		} catch (e: FederationException.FetchingFailed) {
			return null
		}

		val isTrusted = trustInfo.trustAnchorKeys.any {
			jwkTrustAnchorProvider.isTrusted(it)
		};
		val isVerified = true;

		return AgentInformation(
			type = AgentType.VERIFIER,
			domain = trustInfo.leaf.domain,
			displayName = trustInfo.leaf.displayName,
			trustFrameworkId = OIDC_FEDERATION_TRUST_FRAMEWORK_ID,
			logoUri = trustInfo.leaf.logoUri,
			isTrusted = isTrusted,
			isVerified = isVerified,
			identityTrust = null,
			issuanceTrust = null,
			verificationTrust = trustInfo.subordinateStatements.joinToString(separator = "\n"),
		);
	}


	override suspend fun validatePresentationRequest(presentationRequest: PresentationRequest): ValidationInfo {
		// No concept of semantic correctness of a presentation request in this trust framework.
		return ValidationInfo(isValid = true)
	}

	override suspend fun getAllowedDocuments(
		presentationRequest: PresentationRequest,
		includeUsedCredentials: Boolean,
	): List<CredentialModel> {
		// No concept of filtering credentials based on presentation request in this trust framework.
		return documentProvider?.getAllCredentials().orEmpty();
	}
}