/* Copyright 2025 Ubique Innovation AG

Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
 */

package ch.ubique.heidi.trust.framework.swiss

import ch.ubique.heidi.credentials.models.credential.CredentialModel
import ch.ubique.heidi.issuance.metadata.data.CredentialConfiguration
import ch.ubique.heidi.issuance.metadata.data.CredentialIssuerMetadata
import ch.ubique.heidi.presentation.request.PresentationRequest
import ch.ubique.heidi.trust.di.HeidiTrustKoinComponent
import ch.ubique.heidi.trust.framework.DocumentProvider
import ch.ubique.heidi.trust.framework.TrustFramework
import ch.ubique.heidi.trust.framework.ValidationInfo
import ch.ubique.heidi.trust.framework.swiss.extensions.toAgentInformation
import ch.ubique.heidi.trust.framework.swiss.model.TrustData
import ch.ubique.heidi.trust.framework.swiss.model.TrustedIdentity
import ch.ubique.heidi.trust.model.AgentInformation
import ch.ubique.heidi.trust.model.AgentType
import org.koin.core.component.inject

const val SWISS_TRUST_FRAMEWORK_ID : String = "swiss_trust_framework"

class SwissTrustFramework(
	private val documentProvider: DocumentProvider,
) : TrustFramework, HeidiTrustKoinComponent {
	override val frameworkId: String
		get() = SWISS_TRUST_FRAMEWORK_ID

	private val trustRepository by inject<SwissTrustRepository>()

	override suspend fun getIssuerInformation(
		baseUrl: String,
		credentialConfigurationIds: List<String>,
		credentialIssuerMetadata: CredentialIssuerMetadata
	): AgentInformation? {
		val trustData = trustRepository.getIssuanceTrustData(
			baseUrl,
			credentialConfigurationIds,
			credentialIssuerMetadata.credentialConfigurationsSupported
		) ?: return null

		return fromTrustData(trustData)
	}

	override suspend fun getVerifierInformation(requestUri: String, presentationRequest: PresentationRequest, originalRequest: String?): AgentInformation? {
		return trustRepository.getVerificationTrustData(requestUri, presentationRequest, originalRequest)?.let {
			fromTrustData(it)
		}
	}

	override suspend fun validatePresentationRequest(presentationRequest: PresentationRequest): ValidationInfo {
		// The Swiss Trust Framework has no concept of semantic correctness of a presentation request.
		return ValidationInfo(isValid = true)
	}

    override suspend fun getAllowedDocuments(
        presentationRequest: PresentationRequest,
        includeUsedCredentials: Boolean,
    ): List<CredentialModel> {
		// TODO UBMW: Filter the documents based on the presentation request
        return documentProvider
            .getAllCredentials()
            .filter { includeUsedCredentials || it.isUsed ==  false}
    }

	private fun fromTrustData(trustData: TrustData) = fromTrustData(
		identity = trustData.identity,
		baseUrl = trustData.baseUrl,
		type = when (trustData) {
			is TrustData.Issuance -> AgentType.ISSUER
			is TrustData.Verification -> AgentType.VERIFIER
		},
		isTrusted = trustData.isTrusted,
		trustData = trustData
	)

	private fun fromTrustData(
		identity: TrustedIdentity?,
		baseUrl: String,
		type: AgentType,
		isTrusted: Boolean,
		trustData: TrustData
	): AgentInformation {
		return identity.toAgentInformation(type, baseUrl, isTrusted, trustData, this.frameworkId)
	}

}
