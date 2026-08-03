package org.kapunsdk.trust.framework.oidcfederation

import org.kapunsdk.credentials.models.credential.CredentialModel
import org.kapunsdk.issuance.metadata.data.CredentialIssuerMetadata
import org.kapunsdk.presentation.request.PresentationRequest
import org.kapunsdk.trust.framework.DocumentProvider
import org.kapunsdk.trust.framework.JWKTrustAnchorProvider
import org.kapunsdk.trust.framework.TrustFramework
import org.kapunsdk.trust.framework.ValidationInfo
import org.kapunsdk.trust.model.AgentInformation
import org.kapunsdk.trust.model.AgentType
import org.kapunsdk.util.log.Logger
import uniffi.kapun_trust_rust.FederationException
import uniffi.kapun_trust_rust.oidcfTrustChainFromPresentationRequest
import uniffi.kapun_trust_rust.oidcfTrustChainFromUrl

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
			oidcfTrustChainFromUrl(credentialIssuerMetadata.claims.credentialIssuer);
		} catch (e: FederationException) {
			Logger("Federation").error("Federation failed, skipping it", e)
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