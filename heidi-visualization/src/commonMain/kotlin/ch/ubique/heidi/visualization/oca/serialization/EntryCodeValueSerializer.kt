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

package ch.ubique.heidi.visualization.oca.serialization

import ch.ubique.heidi.visualization.oca.model.content.EntryCodeValue
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive

internal object EntryCodeValueSerializer : KSerializer<EntryCodeValue> {

	override val descriptor = PrimitiveSerialDescriptor("EntryCodeValue", PrimitiveKind.STRING)

	override fun deserialize(decoder: Decoder): EntryCodeValue {
		val jsonDecoder = decoder as? JsonDecoder ?: throw IllegalArgumentException("This class can only be deserialized from JSON")
		return when (val jsonElement = jsonDecoder.decodeJsonElement()) {
			is JsonPrimitive -> EntryCodeValue.Reference(jsonElement.content)
			is JsonArray -> EntryCodeValue.Predefined(jsonElement.map { it.jsonPrimitive.content })
			else -> throw IllegalArgumentException("Excpected either JsonPrimitive or JsonArray but was $jsonElement")
		}
	}

	override fun serialize(encoder: Encoder, value: EntryCodeValue) {
		when (value) {
			is EntryCodeValue.Predefined -> encoder.encodeSerializableValue<List<String>>(ListSerializer(String.serializer()),value.keys)
			is EntryCodeValue.Reference -> encoder.encodeString(value.reference)
		}
	}

}
