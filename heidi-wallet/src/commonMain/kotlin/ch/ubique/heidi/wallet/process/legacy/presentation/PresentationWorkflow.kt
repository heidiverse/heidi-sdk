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

package ch.ubique.heidi.wallet.process.legacy.presentation

import ch.ubique.heidi.trust.framework.swiss.model.TrustData
import ch.ubique.heidi.wallet.credentials.presentation.CredentialSelectionUiModel
import ch.ubique.heidi.wallet.credentials.presentation.PresentationUiModel
import ch.ubique.heidi.wallet.process.legacy.ConnectionCheckType
import ch.ubique.heidi.wallet.process.legacy.ProcessWorkflow
import ch.ubique.heidi.wallet.process.presentation.PresentationProcessKt
import uniffi.heidi_util_rust.Value
import uniffi.heidi_wallet_rust.AgentInfo
import uniffi.heidi_wallet_rust.ApiException

//TODO: iOS probably needs to restructure a bit more on the presentation flow
@Deprecated("Deprecated with the new ProcessStep pipeline")
sealed interface PresentationWorkflow : ProcessWorkflow {

    data object Idle: PresentationWorkflow

    data class Loading(val previous: ProcessWorkflow) : PresentationWorkflow

    data object NoMatchingCredential: PresentationWorkflow

    data class ShowAgentDetails(
		val verificationTrustData: TrustData.Verification,
		val agentInfo: AgentInfo,
		val checkType: ConnectionCheckType,
		private val process: PresentationProcessKt,
		private val nextInternal: (TrustData.Verification, PresentationProcessKt, AgentInfo) -> Unit,
    ) : PresentationWorkflow {
        fun next() {
            nextInternal(verificationTrustData, process, agentInfo)
        }
    }

    data class CredentialSelection(
		val verificationTrustData: TrustData.Verification,
		private val state: PresentationProcessKt,
		val viewModel: PresentationUiModel,
		val isProximityPresentation: Boolean,
		val nextInternal: (TrustData.Verification, PresentationProcessKt, HashMap<String,CredentialSelectionUiModel>) -> Unit,
    ) : PresentationWorkflow {
        fun next(selection: HashMap<String,CredentialSelectionUiModel>) {
            nextInternal(this.verificationTrustData, this.state, selection)
        }
    }

    data class EnterPin(
		private val verificationTrustData: TrustData.Verification,
		private val state: PresentationProcessKt,
		private val viewModel: Map.Entry<String, CredentialSelectionUiModel>,
		private val credentialsWithPin:  MutableList<Map.Entry<String, CredentialSelectionUiModel>>,
		private val credentialsWithFrost:  MutableList<Map.Entry<String, CredentialSelectionUiModel>>,
		val nextInternal: (TrustData.Verification, PresentationProcessKt, MutableList<Map.Entry<String, CredentialSelectionUiModel>>, MutableList<Map.Entry<String, CredentialSelectionUiModel>>) -> Unit,
		val needsBiometry: Boolean = false,
		val error: PresentationError? = null,
    ) : PresentationWorkflow {
        fun next(pin: String) {
            this.state.putPin(viewModel.key, pin)
            nextInternal(this.verificationTrustData, this.state, credentialsWithPin, credentialsWithFrost)
        }
    }

    data class EnterPassphrase(
		private val verificationTrustData: TrustData.Verification,
		private val state: PresentationProcessKt,
		private val viewModel: Map.Entry<String, CredentialSelectionUiModel>,
		private val credentialsWithFrost:  MutableList<Map.Entry<String, CredentialSelectionUiModel>>,
		val nextInternal: (TrustData.Verification, PresentationProcessKt, MutableList<Map.Entry<String, CredentialSelectionUiModel>>, MutableList<Map.Entry<String, CredentialSelectionUiModel>>) -> Unit,
		val error: PresentationError? = null,
    ) : PresentationWorkflow {
        fun next(passphrase: String) {
            state.putPassphrase(viewModel.key, passphrase)
            nextInternal(this.verificationTrustData, this.state, mutableListOf() ,credentialsWithFrost)
        }
    }

    data class Success(val message: String, val redirectUri: String? = null, val presentationDuringIssuanceSession: String? = null) :
		PresentationWorkflow
    data class DcApiSuccess(val vpToken: Value) : PresentationWorkflow
    data class ProximitySuccess(val token: ByteArray) : PresentationWorkflow

    data class Error(val code : String, val error : ApiException? = null, val retry: (() -> Unit)? = null) : PresentationWorkflow
}
