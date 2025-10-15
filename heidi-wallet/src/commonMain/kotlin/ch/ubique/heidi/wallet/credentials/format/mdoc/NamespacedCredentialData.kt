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

package ch.ubique.heidi.wallet.credentials.format.mdoc

import ch.ubique.heidi.wallet.extensions.toAttributeValue
import ch.ubique.heidi.visualization.oca.processing.AttributeValue
import com.android.identity.cbor.*
import uniffi.heidi_wallet_rust.VerifiableCredential
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * Similar to the [com.android.identity.document.NameSpacedData] class
 */
class NamespacedCredentialData(
	val data: Map<String, Map<String, AttributeValue<*>>>,
) {

	fun contains(namespace: String, elementIdentifier: String) = data[namespace]?.containsKey(elementIdentifier) ?: false

	operator fun get(namespace: String, elementIdentifier: String): AttributeValue<*>? = data[namespace]?.get(elementIdentifier)

	companion object {

		@OptIn(ExperimentalEncodingApi::class)
		fun fromCredential(credential: VerifiableCredential): NamespacedCredentialData {
			val base64 = Base64.UrlSafe.withPadding(Base64.PaddingOption.PRESENT_OPTIONAL)
			val decoded = Cbor.decode(base64.decode(credential.payload))
			return fromDataItem(decoded["nameSpaces"])
		}

		private fun fromDataItem(mapDataItem: DataItem): NamespacedCredentialData {
			val ret = mutableMapOf<String, MutableMap<String, AttributeValue<*>>>()
			require(mapDataItem is CborMap)
			for (nameSpaceNameItem in mapDataItem.items.keys) {
				require(nameSpaceNameItem is Tstr)
				val namespaceName = nameSpaceNameItem.asTstr
				val dataElementToValueMap = mutableMapOf<String, AttributeValue<*>>()
				when (val dataElementItems = mapDataItem[namespaceName]) {
					is CborMap -> {
						dataElementItems.items.keys.forEach { dataElementNameItem ->
							require(dataElementNameItem is Tstr)
							val dataElementName = dataElementNameItem.asTstr
							val taggedValueItem = dataElementItems[dataElementNameItem]

							require(taggedValueItem is Tagged && taggedValueItem.tagNumber == Tagged.ENCODED_CBOR)
							val valueItem = taggedValueItem.taggedItem
							dataElementToValueMap[dataElementName] = valueItem.toAttributeValue()
						}
					}
					is CborArray -> {
						dataElementItems.items.forEach { dataElementItem ->
							require(dataElementItem is Tagged && dataElementItem.tagNumber == Tagged.ENCODED_CBOR)
							val taggedItem = dataElementItem.asTaggedEncodedCbor
							val elementIdentifier = taggedItem["elementIdentifier"].asTstr
							val elementValue = taggedItem["elementValue"].toAttributeValue()
							dataElementToValueMap[elementIdentifier] = elementValue
						}
					}
					else -> {
						throw IllegalArgumentException("Data elements is must be either map or array")
					}
				}

				ret[namespaceName] = dataElementToValueMap
			}
			return NamespacedCredentialData(ret)
		}
	}

}
