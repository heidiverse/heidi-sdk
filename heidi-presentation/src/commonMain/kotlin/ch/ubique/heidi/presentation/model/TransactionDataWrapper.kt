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

package ch.ubique.heidi.wallet.process.presentation.models

import ch.ubique.heidi.presentation.model.TransactionData
import ch.ubique.heidi.util.extensions.asArray
import ch.ubique.heidi.util.extensions.asString
import ch.ubique.heidi.util.extensions.get
import ch.ubique.heidi.util.extensions.json
import ch.ubique.heidi.util.log.Logger
import kotlinx.serialization.Serializable
import okio.internal.commonToUtf8String
import uniffi.heidi_credentials_rust.SpecVersion
import uniffi.heidi_util_rust.Value
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

@Serializable
sealed class TransactionDataWrapper {

	data class UC5(val value: Map<String, List<Pair<String, TransactionData>>>) : TransactionDataWrapper()
	data class OpenId4Vp(val value: List<Pair<String, TransactionData>>) : TransactionDataWrapper()

	companion object {

		@OptIn(ExperimentalEncodingApi::class)
		fun fromValue(value: Value): TransactionDataWrapper? {
			val uc5TransactionData = value["presentation_definition"]["input_descriptors"].asArray()?.mapNotNull {
				val key = it["id"].asString() ?: return@mapNotNull null

				val value = it["transaction_data"].asArray()?.filterNotNull()?.mapNotNull { transactionData ->
					transactionData.asString()?.let { base64String ->
						Logger.info("decoding transaction data: \"$base64String\"")
						try {
							val jsonString = try {
								Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).decode(base64String).commonToUtf8String()
							} catch (e: Exception) {
								Logger.info("Decoding without padding failed, retrying with padding")
								Base64.UrlSafe.withPadding(Base64.PaddingOption.PRESENT).decode(base64String).commonToUtf8String()
							}
							val decoded = json.decodeFromString<TransactionData>(jsonString)
							Pair(base64String, decoded)
						} catch (ex: Exception) {
							Logger.error("Failed to decode transaction data: \"${base64String}\"  $ex")
							null
						}
					}
				}
				if (value != null) key to value else null
			}?.toMap()

			if (uc5TransactionData != null && uc5TransactionData.isNotEmpty()) {
				return UC5(uc5TransactionData)
			}

			val openId4VpTransactionData = value["transaction_data"].asArray()?.filterNotNull()?.mapNotNull { transactionData ->
				transactionData.asString()?.let { base64String ->
					Logger.info("decoding transaction data: \"$base64String\"")
					try {
						val jsonString = try {
							Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).decode(base64String).commonToUtf8String()
						} catch (e: Exception) {
							Logger.info("Decoding without padding failed, retrying with padding")
							Base64.UrlSafe.withPadding(Base64.PaddingOption.PRESENT).decode(base64String).commonToUtf8String()
						}
						val decoded = json.decodeFromString<TransactionData>(jsonString)
						Pair(base64String, decoded)
					} catch (ex: Exception) {
						Logger.error("Failed to decode transaction data: \"${base64String}\"  $ex")
						null
					}
				}
			}

			if (openId4VpTransactionData != null && openId4VpTransactionData.isNotEmpty()) {
				return OpenId4Vp(openId4VpTransactionData)
			}

			return null;
		}
	}

	fun specVersion(): SpecVersion {
		return when (this) {
			is UC5 -> {
				SpecVersion.POTENTIAL_UC5
			}
			is OpenId4Vp -> {
				SpecVersion.OID4_VP_DRAFT23
			}
		}
	}

	fun getForCredential(id: String): List<Pair<String, TransactionData>>? {
		return when (this) {
			is UC5 -> {
				value.get(id)
			}
			is OpenId4Vp -> {
				value
			}
		}
	}
}
