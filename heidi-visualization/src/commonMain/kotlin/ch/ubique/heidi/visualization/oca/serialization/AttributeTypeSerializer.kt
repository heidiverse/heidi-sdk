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

import ch.ubique.heidi.visualization.extensions.substringBetween
import ch.ubique.heidi.visualization.oca.model.content.AttributeType
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

internal object AttributeTypeSerializer : KSerializer<AttributeType> {

	override val descriptor = PrimitiveSerialDescriptor("AttributeType", PrimitiveKind.STRING)

	override fun deserialize(decoder: Decoder): AttributeType {
		val value = decoder.decodeString()
		return value.toAttributeType()
	}

	override fun serialize(encoder: Encoder, value: AttributeType) {
		encoder.encodeString(value.toStringValue())
	}

	private fun AttributeType.toStringValue(): String = when (this) {
		is AttributeType.Array -> "Array[${contentType.toStringValue()}]"
		AttributeType.Binary -> "Binary"
		AttributeType.Boolean -> "Boolean"
		AttributeType.DateTime -> "DateTime"
		AttributeType.Numeric -> "Numeric"
		AttributeType.Reference -> "Reference"
		AttributeType.Text -> "Text"
		AttributeType.Unknown -> "Unknown"
	}

	private fun String.toAttributeType(): AttributeType = when (this.substringBefore("[")) {
		"Array" -> AttributeType.Array(this.substringBetween("[", "]").toAttributeType())
		"Binary" -> AttributeType.Binary
		"Boolean" -> AttributeType.Boolean
		"DateTime" -> AttributeType.DateTime
		"Numeric" -> AttributeType.Numeric
		"Reference" -> AttributeType.Reference
		"Text" -> AttributeType.Text
		else -> AttributeType.Unknown
	}

}
