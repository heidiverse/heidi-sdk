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

package ch.ubique.heidi.wallet.process.presentation

import ch.ubique.heidi.presentation.request.PresentationRequest
import ch.ubique.heidi.trust.TrustFlow
import ch.ubique.heidi.trust.TrustFrameworkController
import io.ktor.http.Url

abstract class PresentationProcess(
	private val trustController2: TrustFrameworkController,
) {

	protected lateinit var trustFlow: TrustFlow

	protected suspend fun initializeMetadata(qrCodeData: String, origin: String? = null, presentationRequest: PresentationRequest, originalRequest: String?): Result<Unit> {
		val url = runCatching { Url(qrCodeData) }.getOrNull() ?: run {
			trustFlow = startVerificationFlow("", presentationRequest, originalRequest).getOrElse { return Result.failure(it) }
			return Result.success(Unit)
		}
		val requestUri = url.parameters["request_uri"] ?: run {
			trustFlow = startVerificationFlow(url.host, presentationRequest, originalRequest).getOrElse { return Result.failure(it) }
			return Result.success(Unit)
		}

		trustFlow = startVerificationFlow(requestUri, presentationRequest, originalRequest).getOrElse { return Result.failure(it) }
		return Result.success(Unit)
	}

	protected open suspend fun startVerificationFlow(requestUri: String, presentationRequest: PresentationRequest, originalRequest: String?): Result<TrustFlow> {
		return runCatching {
			trustController2.startVerificationFlow(requestUri, presentationRequest, originalRequest)
		}
	}

}
