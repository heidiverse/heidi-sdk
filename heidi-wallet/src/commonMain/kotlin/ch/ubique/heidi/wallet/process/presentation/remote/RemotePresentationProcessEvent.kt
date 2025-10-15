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

import ch.ubique.heidi.wallet.credentials.presentation.CredentialSelectionUiModel
import ch.ubique.heidi.wallet.process.ProcessEvent

sealed interface RemotePresentationProcessEvent : ProcessEvent {

	data class PresentationRequested(
		val qrCodeData: String,
		val presentationScope: String? = null,
		val authSession: String? = null,
		val isDCApi: Boolean = false,
		val selectedId : String? = null,
		val origin: String? = null
	) : RemotePresentationProcessEvent

	data class PinEntered(
		val pin: String,
		val viewModel: Map.Entry<String, CredentialSelectionUiModel>,
		val credentialsWithPin: List<Map.Entry<String, CredentialSelectionUiModel>>,
		val credentialsWithFrost: List<Map.Entry<String, CredentialSelectionUiModel>>,
	) : RemotePresentationProcessEvent

	data class PassphraseEntered(
		val passphrase: String,
		val viewModel: Map.Entry<String, CredentialSelectionUiModel>,
		val credentialsWithFrost: List<Map.Entry<String, CredentialSelectionUiModel>>,
	) : RemotePresentationProcessEvent

	data class CredentialSelected(
		val credentialMapping: Map<String, CredentialSelectionUiModel>,
	) : RemotePresentationProcessEvent

	/**
	 * User requested to try loading new tokens (refresh/issuance handled externally by UI).
	 * After external refresh completes, the handler will call continueWithCredentialSelection() again.
	 */
	data object RefreshRequested : RemotePresentationProcessEvent

	/**
	 * User requested to fallback to a random selection of used-but-valid credentials.
	 */
	data object FallbackRandomRequested : RemotePresentationProcessEvent
}
