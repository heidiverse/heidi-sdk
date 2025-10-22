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
package ch.ubique.heidi.sample.wallet.feature.proximity

import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import ch.ubique.heidi.credentials.ClaimsPointer
import ch.ubique.heidi.credentials.SdJwt
import ch.ubique.heidi.credentials.toClaimsPointer
import ch.ubique.heidi.dcql.Attribute
import ch.ubique.heidi.dcql.AttributeType
import ch.ubique.heidi.dcql.getVpToken
import ch.ubique.heidi.dcql.sdJwtDcqlClaimsFromAttributes
import ch.ubique.heidi.presentation.request.PresentationRequest
import ch.ubique.heidi.proximity.ProximityProtocol
import ch.ubique.heidi.proximity.documents.DocumentRequest
import ch.ubique.heidi.proximity.wallet.ProximityWallet
import ch.ubique.heidi.proximity.wallet.ProximityWalletState
import ch.ubique.heidi.util.extensions.toCbor
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import org.koin.core.component.KoinComponent
import org.koin.core.module.dsl.viewModelOf
import org.koin.dsl.module
import uniffi.heidi_credentials_rust.SignatureCreator
import uniffi.heidi_crypto_rust.SoftwareKeyPair
import uniffi.heidi_dcql_rust.CredentialQuery
import uniffi.heidi_dcql_rust.DcqlQuery
import uniffi.heidi_dcql_rust.Meta
import uniffi.heidi_util_rust.Value
import kotlin.String
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

@OptIn(ExperimentalUuidApi::class)
class ProximityViewModel : ViewModel(), KoinComponent {

	companion object {
		val koinModule = module {
			viewModelOf(::ProximityViewModel)
		}
	}

	private lateinit var wallet: ProximityWallet

	private val proximityStateMutable = MutableStateFlow<ProximityWalletState>(ProximityWalletState.Initial)
	val proximityState = proximityStateMutable.asStateFlow()

	override fun onCleared() {
		super.onCleared()
		wallet.disconnect()
	}

	fun startEngagement(qrCodeData: String) {
		viewModelScope.launch {
			val qrCodeUri = Uri.parse(qrCodeData)
			val verifierName = qrCodeUri.getQueryParameter("name")!!
			val publicKey = qrCodeUri.getQueryParameter("key")
			val serviceUuid = Uuid.parse(qrCodeUri.getQueryParameter("uuid")!!)

			wallet = ProximityWallet.create(ProximityProtocol.OPENID4VP, viewModelScope, serviceUuid)
			wallet.startEngagement(verifierName)
			startCollectingWalletState()
		}
	}
	fun startEngagementMdl() {
		viewModelScope.launch {
			val serviceUuid = Uuid.random()
			val peripheralUuid = Uuid.random()
			wallet = ProximityWallet.create(ProximityProtocol.MDL, viewModelScope, serviceUuid, peripheralUuid)
			wallet.startEngagement("")
			startCollectingWalletState()
		}
	}

	fun submitDocument() {
		viewModelScope.launch {
			val sdjwt = SdJwt.create(claims = mapOf<String, Any>(
				"vct" to "beta-id",
				"firstName" to "Pascal",
				"lastName" to "Tester",
				"age_over_16" to true,
				"age_over_18" to true,
				"age_over_65" to false
			).toCbor(),
				disclosures = listOf(
					listOf("firstName").toClaimsPointer()!!,
					listOf("lastName").toClaimsPointer()!!,
					listOf("age_over_16").toClaimsPointer()!!,
					listOf("age_over_18").toClaimsPointer()!!,
					listOf("age_over_65").toClaimsPointer()!!,
				),
				keyId = "keyId", key = TestSigner(SoftwareKeyPair()), null)
			val credentialQuery = dcqlQuery!!.credentials?.first()!!
			val vpToken = sdjwt!!.getVpToken(
				credentialQuery,
				"test",
				null,
				null,
				"",
				null
			).getOrThrow()
			wallet.submitDocument(Json.encodeToString(mapOf<String, String>(
				"test" to vpToken
			)).encodeToByteArray())
		}
	}
	var dcqlQuery : DcqlQuery? = null
	private fun startCollectingWalletState() {
		viewModelScope.launch {
			wallet.walletState.collect { state ->
				proximityStateMutable.value = state
				if (state is ProximityWalletState.RequestingDocuments) {
					if(state.request is DocumentRequest.OpenId4Vp) {
						val v : Value = Json.decodeFromString<Value>((state.request as DocumentRequest.OpenId4Vp).parJwt)
						var pr = PresentationRequest.fromValue(v)
						dcqlQuery = pr!!.dcqlQuery
					}
				}
			}
		}
	}
	fun reset() {
		wallet.disconnect()
	}
}

class TestSigner(private val kp : SoftwareKeyPair) : SignatureCreator {
	override fun alg(): String {
		return "ES256"
	}

	override fun sign(bytes: ByteArray): ByteArray {
		return kp.signWithKey(bytes)
	}
}