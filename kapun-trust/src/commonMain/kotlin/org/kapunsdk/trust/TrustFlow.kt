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

package org.kapunsdk.trust

import org.kapunsdk.credentials.models.credential.CredentialModel
import org.kapunsdk.presentation.request.PresentationRequest
import org.kapunsdk.trust.framework.TrustFramework
import org.kapunsdk.trust.framework.ValidationInfo
import org.kapunsdk.trust.model.AgentInformation

class TrustFlow(
	val agentInformation: AgentInformation,
	private val framework: org.kapunsdk.trust.framework.TrustFramework?,
) {

	suspend fun validatePresentationRequest(
		presentationRequest: PresentationRequest,
	): org.kapunsdk.trust.framework.ValidationInfo {
		return framework?.validatePresentationRequest(presentationRequest) ?: _root_ide_package_.org.kapunsdk.trust.framework.ValidationInfo(
			isValid = false,
			errorInfo = "invalid_request"
		)
	}

	suspend fun getAllowedDocuments(
		presentationRequest: PresentationRequest,
		includeUsedCredentials: Boolean,
	): List<CredentialModel> {
		return framework?.getAllowedDocuments(presentationRequest, includeUsedCredentials) ?: emptyList()
	}

}
