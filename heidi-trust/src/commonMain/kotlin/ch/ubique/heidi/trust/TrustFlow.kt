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

import ch.ubique.heidi.credentials.models.credential.CredentialModel
import ch.ubique.heidi.presentation.request.PresentationRequest
import ch.ubique.heidi.trust.framework.TrustFramework
import ch.ubique.heidi.trust.framework.ValidationInfo
import ch.ubique.heidi.trust.model.AgentInformation

class TrustFlow(
	val agentInformation: AgentInformation,
	private val framework: TrustFramework?,
) {

	suspend fun validatePresentationRequest(
		presentationRequest: PresentationRequest,
	): ValidationInfo {
		return framework?.validatePresentationRequest(presentationRequest) ?: ValidationInfo(isValid = false, errorInfo = "invalid_request")
	}

	suspend fun getAllowedDocuments(
		presentationRequest: PresentationRequest,
		includeUsedCredentials: Boolean,
	): List<CredentialModel> {
		return framework?.getAllowedDocuments(presentationRequest, includeUsedCredentials) ?: emptyList()
	}

}
