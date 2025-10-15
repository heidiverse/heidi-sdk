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

package ch.ubique.heidi.trust

import ch.ubique.heidi.issuance.metadata.data.CredentialIssuerMetadata
import ch.ubique.heidi.presentation.request.PresentationRequest
import ch.ubique.heidi.trust.framework.TrustFramework
import ch.ubique.heidi.trust.model.AgentInformation
import ch.ubique.heidi.trust.model.AgentType

class TrustFrameworkController(
	private val frameworks: List<TrustFramework>,
) {
	suspend fun startIssuanceFlow(
		baseUrl: String,
		credentialConfigurationIds: List<String>,
		credentialIssuerMetadata: CredentialIssuerMetadata
	): TrustFlow {
		return startFlow { framework ->
			framework.getIssuerInformation(baseUrl, credentialConfigurationIds, credentialIssuerMetadata)
		} ?: createUntrustedFlow(baseUrl, AgentType.ISSUER)
	}

	suspend fun startVerificationFlow(
		requestUri: String,
		presentationRequest: PresentationRequest,
		originalRequest: String?
	): TrustFlow {
		return startFlow { framework ->
			framework.getVerifierInformation(requestUri, presentationRequest, originalRequest)
		} ?: createUntrustedFlow(requestUri, AgentType.VERIFIER)
	}

	private suspend fun startFlow(agentProvider: suspend (TrustFramework) -> AgentInformation?): TrustFlow? {
		frameworks.forEach { framework ->
			val agentInformation = agentProvider.invoke(framework)
			if (agentInformation != null) {
				return TrustFlow(agentInformation, framework)
			}
		}

		return null
	}

	private fun createUntrustedFlow(baseUrl: String, agentType: AgentType) = TrustFlow(
		agentInformation = AgentInformation(
			type = agentType,
			domain = baseUrl,
			displayName = baseUrl,
			logoUri = null,
			isTrusted = false,
			isVerified = false,
			trustFrameworkId = null,
		),
		framework = null,
	)

}
