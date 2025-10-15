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

package ch.ubique.heidi.wallet.process.legacy

import ch.ubique.heidi.wallet.credentials.identity.IdentityUiModel
import uniffi.heidi_wallet_rust.ApiException

//TODO: How can we have such common errors in the sealed interfaces of issuance and/or presentation?
@Deprecated("Deprecated with the new ProcessStep pipeline")
interface ProcessWorkflow {
	data class Idle(
		val startEidIssuance: (String?) -> Unit,
		val startPresentation: () -> Unit,
		val startRegisterEmergencyPass: (IdentityUiModel) -> Unit
	) : ProcessWorkflow

	data class Loading(val previous: ProcessWorkflow) : ProcessWorkflow

	data class Error(
		val code : String,
		val error : ApiException? = null,
		val retry: (() -> Unit)? = null
	) : ProcessWorkflow
}
