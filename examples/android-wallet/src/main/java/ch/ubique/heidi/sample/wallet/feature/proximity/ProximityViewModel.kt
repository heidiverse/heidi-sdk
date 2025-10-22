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

	/**
	 * Start a engagement via QR-Code for a ISO mdl flow
	 */
	fun startEngagementMdl() {
		viewModelScope.launch {
			val serviceUuid = Uuid.random()
			val peripheralUuid = Uuid.random()
			// The wallet chooses to use one of the two (or both modes).
			wallet = ProximityWallet.create(ProximityProtocol.MDL, viewModelScope, serviceUuid, peripheralUuid)
			wallet.startEngagement("")
			startCollectingWalletState()
		}
	}

	fun submitDocument() {
		viewModelScope.launch {
			//TODO: allow this credential to be chosen from UI (e.g. to test verification of properties like age)
			// on the check app
			val sdjwt = SdJwt.create(claims = mapOf<String, Any>(
				//TODO: add necessary exp, nbf, iat claims here, so we can check integrity on the check app
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
				//TODO: Ideally we have a pubKeyJwk here and a signer, to actually sign the KB-JWT for verification
				keyId = "keyId", key = TestSigner(SoftwareKeyPair()), null)
			//TODO: ideally we would use the dcqlquery's select credential function with a database of tokens (c.f. in the wallet module)
			val credentialQuery = dcqlQuery!!.credentials?.first()!!
			val vpToken = sdjwt!!.getVpToken(
				credentialQuery,
				//TODO: double check what the audience in our flow should be
				"test",
				null,
				null,
				"",
				null
			).getOrThrow()
			wallet.submitDocument(Json.encodeToString(mapOf<String, String>(
				credentialQuery.id to vpToken
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
						//TODO: this is probably signed (or at least it could be signed) we need to check the signature
						// and then check that verifier_info contains a wallet attestation attesting to the key used for signing the request
						val v : Value = Json.decodeFromString<Value>((state.request as DocumentRequest.OpenId4Vp).parJwt)
						var pr = PresentationRequest.fromValue(v)
						//TODO: we would want to check if `origin`, which the wallet calculated itself, is actually found in expected
						// origins of the request.
//						(state.request as DocumentRequest.OpenId4Vp).origin
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