/* Copyright 2024 Ubique Innovation AG

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
package ch.ubique.heidi.proximity.wallet

import ch.ubique.heidi.proximity.ProximityError
import ch.ubique.heidi.proximity.documents.DocumentRequest
import ch.ubique.heidi.proximity.verifier.ProximityVerifierState

sealed interface ProximityWalletState {

	/** Initial state */
	data object Initial : ProximityWalletState
	/** The verifier is ready for engagement */
	data class ReadyForEngagement(val qrCodeData: String) : ProximityWalletState

	/** The wallet has engaged and is connecting to a verifier */
	data class Connecting(val verifierName: String) : ProximityWalletState

	/** The wallet has successfully connected to a verifier */
	data class Connected(val verifierName: String) : ProximityWalletState

	/** A document request has been received */
	data class RequestingDocuments(val request: DocumentRequest) : ProximityWalletState

	/** The wallet is sending the documents to the verifier and is waiting for its result */
	data class SubmittingDocuments(val progress: Double? = null) : ProximityWalletState

	/** The verifier has received the requested documents */
	data object PresentationCompleted : ProximityWalletState

	/** The connection with the verifier has been closed */
	data object Disconnected : ProximityWalletState

	/** An error has occured during the proximity verification */
	data class Error(val error: ProximityError) : ProximityWalletState
}
