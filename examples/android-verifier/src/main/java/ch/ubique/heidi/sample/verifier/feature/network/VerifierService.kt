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
package ch.ubique.heidi.sample.verifier.feature.network

import ch.ubique.heidi.sample.verifier.data.dto.VerificationDisclosureDto
import ch.ubique.heidi.sample.verifier.data.dto.VerificationRequestDto
import de.jensklingenberg.ktorfit.http.*

interface VerifierService {

	@FormUrlEncoded
	@POST("v1/verifier/par")
	suspend fun getVerificationRequest(
		@Field("credentialRequest") credentialRequest: String,
	): VerificationRequestDto

	@GET("v1/wallet/par/{requestUri}")
	suspend fun getPresentationDefinition(
		@Path("requestUri") requestUri: String
	): String

	@POST("v1/wallet/authorization")
	suspend fun verifyDocuments(
		@Body response: String,
		@Header("Content-Type") contentType: String = "application/x-www-form-urlencoded",
	)

	@GET("v1/verifier/authorization")
	suspend fun getAuthorization(
		@Query("transactionId") transactionId: String? = null,
	): VerificationDisclosureDto

}
