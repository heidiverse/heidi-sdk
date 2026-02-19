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
package ch.ubique.heidi.proximity.verifier

import ch.ubique.heidi.proximity.ProximityError

sealed interface ProximityVerifierState {

	/** Initial state */
	data object Initial : ProximityVerifierState

	/** The proximity engagement data is being loaded */
	data object PreparingEngagement : ProximityVerifierState

	/** The verifier is ready for engagement */
	data class ReadyForEngagement(val qrCodeData: String) : ProximityVerifierState

	/** A wallet has engaged and is connecting to this verifier */
	data object Connecting : ProximityVerifierState

	/** A wallet has successfully connected to this verifier */
	data object Connected : ProximityVerifierState

	/** The verifier is sending the document request to the wallet and is waiting for its documents */
	data object AwaitingDocuments : ProximityVerifierState

	/** The verifier has received the requested documents and verified them */
	data class VerificationResult<T>(val result: T) : ProximityVerifierState

	/** The wallet terminated the session with a reason (e.g., user declined) */
	data class Terminated(val reason: TerminationReason) : ProximityVerifierState

	/** The connection with the wallet has been closed */
	data object Disconnected : ProximityVerifierState

	/** An error has occured during the proximity verification */
	data class Error(val error: ProximityError) : ProximityVerifierState

}

// Status codes follow ISO-18013-5 / Table 8 SessionData.status values.
enum class TerminationReason(val code: Long) {
    GENERAL_ERROR(10),
    READER_AUTHENTICATION_ERROR(20),
    REQUEST_REJECTED(21),
    UNKNOWN(-1);

	companion object {
		fun fromCode(code: Long): TerminationReason = values().firstOrNull { it.code == code } ?: UNKNOWN
	}
}
