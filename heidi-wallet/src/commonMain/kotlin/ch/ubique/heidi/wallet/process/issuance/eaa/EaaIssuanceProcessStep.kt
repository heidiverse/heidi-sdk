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

package ch.ubique.heidi.wallet.process.issuance.eaa

import ch.ubique.heidi.trust.model.AgentInformation
import ch.ubique.heidi.wallet.credentials.identity.IdentityUiModel
import ch.ubique.heidi.wallet.extensions.asErrorState
import ch.ubique.heidi.wallet.process.ProcessStep
import uniffi.heidi_wallet_rust.ApiException
import uniffi.heidi_wallet_rust.CredentialOfferAuthType
import uniffi.heidi_wallet_rust.GenericException

sealed interface EaaIssuanceProcessStep : ProcessStep {

	data class Error(
		val errorMessage: String,
		val errorCode: String? = null,
		val cause: Exception? = null,
		val retry: (() -> Unit)? = null,
	) : EaaIssuanceProcessStep

	data class ConnectionDetails(
		val agentInformation: AgentInformation,
	) : EaaIssuanceProcessStep

	data class CredentialOfferPreview(
		val agentInformation: AgentInformation,
		val authType: CredentialOfferAuthType,
	) : EaaIssuanceProcessStep

	data class Presentation(
		val presentationData: String,
		val presentationScope: String,
		val authSession: String,
	) : EaaIssuanceProcessStep

	data class TransactionCode(
		val isNumeric: Boolean,
		val length: Int? = null,
		val description: String? = null,
	) : EaaIssuanceProcessStep

	data class PushedAuthorization(
		val url: String,
	) : EaaIssuanceProcessStep

	data class CredentialOffer(
		val agentInformation: AgentInformation,
		val viewModel: IdentityUiModel,
	) : EaaIssuanceProcessStep

	data object Success : EaaIssuanceProcessStep

}
