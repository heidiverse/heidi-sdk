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

package ch.ubique.heidi.wallet.process.presentation.remote

import ch.ubique.heidi.presentation.model.DocumentDigest
import ch.ubique.heidi.presentation.model.TransactionData
import ch.ubique.heidi.trust.framework.ValidationInfo
import ch.ubique.heidi.trust.model.AgentInformation
import ch.ubique.heidi.wallet.credentials.presentation.CredentialSelectionUiModel
import ch.ubique.heidi.wallet.credentials.presentation.PresentationUiModel
import ch.ubique.heidi.wallet.extensions.asErrorState
import ch.ubique.heidi.wallet.process.ProcessStep
import ch.ubique.heidi.wallet.process.legacy.presentation.PresentationError
import ch.ubique.heidi.wallet.process.presentation.ErrorModel
import ch.ubique.heidi.wallet.process.presentation.PresentationStep
import uniffi.heidi_wallet_rust.ApiException
import uniffi.heidi_wallet_rust.GenericException

sealed interface RemotePresentationProcessStep : ProcessStep {

	data class Error(
		val errorMessage: String,
		val errorCode: String? = null,
		val cause: Exception? = null,
		val retry: (() -> Unit)? = null,
	) : RemotePresentationProcessStep

	data class ConnectionDetails(
		val agentInformation: AgentInformation,
	) : RemotePresentationProcessStep

	sealed interface QesProcessStep : ProcessStep {
		data class Preview(
			val agentInformation: AgentInformation,
		) : QesProcessStep

		data class CreationAcceptance(
			val agentInformation: AgentInformation,
			val documents: List<TransactionData>
		) : QesProcessStep

		data class SignDocument(
			val agentInformation: AgentInformation,
			val documents: List<DocumentDigest>
		) : QesProcessStep
	}

	data class CredentialSelection(
		override val presentationModel: PresentationUiModel,
		override val agentInformation: AgentInformation,
		override val validationInfo: ValidationInfo? = null
	) : RemotePresentationProcessStep, PresentationStep.CredentialSelection


    data class OutOfTokens(
        val isRefreshable: Boolean,
        val identityIdsToRefresh: Set<Long> = emptySet(),
        val error: ErrorModel? = null,
    ) : RemotePresentationProcessStep

	data class EnterPin(
		val viewModel: Map.Entry<String, CredentialSelectionUiModel>,
		val credentialsWithPin: MutableList<Map.Entry<String, CredentialSelectionUiModel>>,
		val credentialsWithFrost: MutableList<Map.Entry<String, CredentialSelectionUiModel>>,
		val needsBiometry: Boolean = false,
		val error: PresentationError? = null,
	) : RemotePresentationProcessStep

	data class EnterPassphrase(
		val viewModel: Map.Entry<String, CredentialSelectionUiModel>,
		val credentialsWithFrost: MutableList<Map.Entry<String, CredentialSelectionUiModel>>,
		val error: PresentationError? = null,
	) : RemotePresentationProcessStep

	data class DcApiSuccess(val token: String) : RemotePresentationProcessStep

	data class Success(
		val message: String,
		val redirectUri: String? = null,
		val presentationScope: String? = null,
		val authSession: String? = null,
		val pdiSession: String? = null,
		val isQes: Boolean = false,
	) : RemotePresentationProcessStep

}
