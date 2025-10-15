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

package ch.ubique.heidi.wallet.process.vc2pdf

import ch.ubique.heidi.util.log.Logger
import ch.ubique.heidi.wallet.extensions.asErrorState
import io.ktor.client.HttpClient
import io.ktor.client.request.accept
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.statement.bodyAsBytes
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.contentType
import kotlinx.serialization.json.Json
import kotlinx.serialization.Serializable
import uniffi.heidi_wallet_rust.ApiException



class Vc2PdfProcess(
	private val client: HttpClient,
	private val baseUrl: String,
) {

	suspend fun initiateCredentialToPdf(flowId: String): Vc2PdfProcessStep {
		return try {
			// Call /v1/pdf-flows/{flowId}/initiate to get presentation URL
			val response = client.post("${baseUrl}/v1/pdf-flows/${flowId}/initiate") {
				contentType(ContentType.Application.Json)
				accept(ContentType.Application.Json)
			}
			
			val responseText = response.bodyAsText()
			Logger.debug("received VC2PDF initiate response: $responseText")

			Vc2PdfProcessStep.PresentationRequired(responseText)
		} catch (e: ApiException) {
			val info = e.asErrorState()
			Vc2PdfProcessStep.Error(
				errorMessage = info.messageOrCode, 
				errorCode = info.code, 
				cause = info.cause
			)
		} catch (e: Exception) {
			Logger.error("Vc2PdfProcess: Error initiating credential to PDF conversion", e)
			Vc2PdfProcessStep.Error(
				errorMessage = e.message ?: e::class.simpleName ?: "Unknown error", 
				cause = e
			)
		}
	}

	suspend fun handlePresentationCompleted(redirectUri: String): Vc2PdfProcessStep {
		Logger.debug("handlePresentationCompleted redirectUri: $redirectUri")
		return try {
			// Extract transaction ID from redirect URI (after #)
			val transactionId = extractTransactionIdFromUri(redirectUri)
				?: return Vc2PdfProcessStep.Error(
					errorMessage = "Could not extract transaction ID from redirect URI: $redirectUri"
				)

			Logger.debug("handlePresentationCompleted transactionId: $transactionId")

			// Call /v1/pdf-flows/transaction/{transactionId}/pdf to get the PDF
			val response = client.get("${baseUrl}/v1/pdf-flows/transaction/$transactionId/pdf") {
				accept(ContentType.Application.Pdf)
			}

			val pdfData = response.bodyAsBytes()
			Logger.debug("Vc2PdfProcess: Retrieved PDF data, size: ${pdfData.size} bytes")
			
			Vc2PdfProcessStep.Success(pdfData, transactionId)
		} catch (e: ApiException) {
			val info = e.asErrorState()
			Logger.error("Vc2PdfProcess: Error retrieving PDF: ${info.messageOrCode}", e)
			Vc2PdfProcessStep.Error(
				errorMessage = info.messageOrCode,
				errorCode = info.code,
				cause = info.cause
			)
		} catch (e: Exception) {
			Logger.error("Vc2PdfProcess: Error handling presentation completion", e)
			Vc2PdfProcessStep.Error(
				errorMessage = e.message ?: e::class.simpleName ?: "Unknown error",
				cause = e
			)
		}
	}

	private fun extractTransactionIdFromUri(redirectUri: String): String? {
		return redirectUri.substringAfter("#", "").takeIf { it.isNotEmpty() }
	}

}
