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

package ch.ubique.heidi.wallet.process.signing.qes

import ch.ubique.heidi.trust.TrustFrameworkController
import ch.ubique.heidi.trust.TrustFlow
import ch.ubique.heidi.util.log.Logger
import ch.ubique.heidi.wallet.credentials.ViewModelFactory
import ch.ubique.heidi.wallet.credentials.activity.ActivityRepository
import ch.ubique.heidi.wallet.credentials.credential.CredentialsRepository
import ch.ubique.heidi.wallet.credentials.identity.IdentityRepository
import ch.ubique.heidi.wallet.credentials.signeddocument.SignedDocumentsRepository
import ch.ubique.heidi.wallet.crypto.SigningProvider
import ch.ubique.heidi.wallet.extensions.asErrorState
import ch.ubique.heidi.wallet.keyvalue.KeyValueRepository
import io.ktor.client.HttpClient
import io.ktor.client.request.accept
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsBytes
import io.ktor.http.ContentType
import io.ktor.http.contentType
import kotlinx.serialization.json.Json
import kotlinx.serialization.Serializable
import uniffi.heidi_crypto_rust.sha256Rs
import uniffi.heidi_wallet_rust.ApiException

@Serializable
private data class QesInitiateResponse(
	val sameDevice: QrCodeData,
	val crossDevice: QrCodeData
)

@Serializable
private data class QrCodeData(
	val qrCodeDataPath: String,
	val qrCodeDataScheme: String,
	val connectionId: String
)

@Serializable
private data class QesInitiateRequest(
	val documentHash: String,
	val hashAlgorithmOID: String
)

class QesPdfSigningProcess(
	private val client: HttpClient,
	private val signedDocumentsRepository: SignedDocumentsRepository,
	private val json: Json,
	private val baseUrl: String,
) {

	private var currentPdfData: ByteArray? = null
	private var currentPdfFileName: String? = null
	private var trustFlow: TrustFlow? = null

	@OptIn(ExperimentalStdlibApi::class)
	suspend fun initiatePdfSigning(pdfData: ByteArray, fileName: String): QesPdfSigningProcessStep {
		return try {
			currentPdfData = pdfData
			currentPdfFileName = fileName
			
			// Compute SHA256 hash of the PDF data
			val documentHash = sha256Rs(pdfData).toHexString()
			
			// Create the request payload
			val requestPayload = QesInitiateRequest(
				documentHash = documentHash,
				hashAlgorithmOID = "2.16.840.1.101.3.4.2.1" // SHA-256
			)
			
			// Call /v1/wallet/qes/initiate to get OpenID4VP string
			val openId4VpResponse = client.post("${baseUrl}/v1/wallet/qes/initiate") {
				contentType(ContentType.Application.Json)
				setBody(json.encodeToString(QesInitiateRequest.serializer(), requestPayload))
			}
			
			val responseJson = openId4VpResponse.bodyAsBytes().decodeToString()
			Logger.debug("received QES initiate response: $responseJson")
			
			// Parse JSON response
			val qesResponse = json.decodeFromString<QesInitiateResponse>(responseJson)
			
			// Construct OpenID4VP string from sameDevice data
			val openId4VpString = "${qesResponse.sameDevice.qrCodeDataScheme}${qesResponse.sameDevice.qrCodeDataPath}"
			
			Logger.debug("constructed openId4VpString: $openId4VpString")
			
			QesPdfSigningProcessStep.PresentationRequired(openId4VpString, pdfData)
		} catch (e: ApiException) {
			val info = e.asErrorState()
			QesPdfSigningProcessStep.Error(
				errorMessage = info.messageOrCode, 
				errorCode = info.code, 
				cause = info.cause
			)
		} catch (e: Exception) {
			Logger.error("QesPdfSigningProcess: Error initiating PDF signing", e)
			QesPdfSigningProcessStep.Error(
				errorMessage = e.message ?: e::class.simpleName ?: "Unknown error", 
				cause = e
			)
		}
	}

	suspend fun handlePresentationCompleted(redirectUri: String): QesPdfSigningProcessStep {
		Logger.debug("handlePresentationCompleted redirectUri: $redirectUri")

		val pdfData = currentPdfData
			?: return QesPdfSigningProcessStep.Error(errorMessage = "PDF data is missing")

		return try {
			// Extract transaction ID from redirect URI
			val transactionId = extractTransactionIdFromUri(redirectUri)
				?: return QesPdfSigningProcessStep.Error(
					errorMessage = "Could not extract transaction ID from redirect URI: $redirectUri"
				)

			Logger.debug("handlePresentationCompleted transactionId: $transactionId")

			Logger.debug("QesPdfSigningProcess: Signing PDF with transaction ID: $transactionId")

			// Call /v1/wallet/qes/transaction/<transaction-ID>/sign-pdf
			val response = client.post("${baseUrl}/v1/wallet/qes/transaction/$transactionId/sign-pdf") {
				contentType(ContentType.Application.Pdf)
				accept(ContentType.Application.Pdf)
				setBody(pdfData)
			}

			val signedPdfData = response.bodyAsBytes()

			val fileName = currentPdfFileName ?: "signed_document.pdf"
			signedDocumentsRepository.insertSignedDocument(
				fileName = fileName,
				fileData = signedPdfData,
				transactionId = transactionId
			)
			Logger.debug("QesPdfSigningProcess: Stored signed document in database")

			QesPdfSigningProcessStep.Success(signedPdfData, transactionId)
		} catch (e: ApiException) {
			val info = e.asErrorState()
			Logger.error("QesPdfSigningProcess: Error signing PDF: ${info.messageOrCode}", e)
			QesPdfSigningProcessStep.Error(
				errorMessage = info.messageOrCode,
				errorCode = info.code,
				cause = info.cause
			)
		} catch (e: Exception) {
			Logger.error("QesPdfSigningProcess: Error handling presentation completion", e)
			QesPdfSigningProcessStep.Error(
				errorMessage = e.message ?: e::class.simpleName ?: "Unknown error",
				cause = e
			)
		}
	}

	private fun extractTransactionIdFromUri(redirectUri: String): String? {
		return redirectUri.substringAfter("#", "").takeIf { it.isNotEmpty() }
	}

}
