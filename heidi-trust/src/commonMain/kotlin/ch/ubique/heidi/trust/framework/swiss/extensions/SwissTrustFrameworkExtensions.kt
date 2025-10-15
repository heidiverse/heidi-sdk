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

package ch.ubique.heidi.trust.framework.swiss.extensions

import ch.ubique.heidi.trust.framework.swiss.model.TrustData
import ch.ubique.heidi.trust.framework.swiss.model.TrustedIdentity
import ch.ubique.heidi.trust.model.AgentInformation
import ch.ubique.heidi.trust.model.AgentType
import ch.ubique.heidi.util.platform.Platform

fun TrustedIdentity?.toAgentInformation(
	agentType: AgentType,
	baseUrl: String,
	isTrusted: Boolean,
	trustData: TrustData,
	frameworkId: String?
): AgentInformation {
	val userLanguage = Platform.getCurrentLocale()
	return AgentInformation(
		type = agentType,
		domain = baseUrl,
		displayName = this?.entityName?.let { entityName ->
			entityName[userLanguage]
				?: this.prefLang?.let { entityName[it] }
				?: entityName.values.firstOrNull()
		} ?: baseUrl,
		logoUri = this?.logoUri?.let { logoUri ->
			logoUri[userLanguage]
				?: this.prefLang?.let { logoUri[it] }
				?: logoUri.values.firstOrNull()
		},
		isTrusted = isTrusted,
		isVerified = trustData.isVerified,
		identityTrust = trustData.identityJwt,
		issuanceTrust = (trustData as? TrustData.Issuance)?.issuanceJwt,
		verificationTrust = (trustData as? TrustData.Verification)?.verificationJwt,
		trustFrameworkId = frameworkId
	)
}
