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

import ch.ubique.heidi.visualization.oca.model.content.Cardinality
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

internal object CardinalitySerializer : KSerializer<Cardinality> {

	override val descriptor = PrimitiveSerialDescriptor("Cardinality", PrimitiveKind.STRING)

	override fun deserialize(decoder: Decoder): Cardinality {
		val value = decoder.decodeString()
		return when (val delimiterIndex = value.indexOf("-")) {
			-1 -> Cardinality.Exactly(value.toInt())
			0 -> Cardinality.AtMost(value.drop(1).toInt())
			value.lastIndex -> Cardinality.AtLeast(value.dropLast(1).toInt())
			else -> Cardinality.Between(value.substring(0, delimiterIndex).toInt(), value.substring(delimiterIndex + 1).toInt())
		}
	}

	override fun serialize(encoder: Encoder, value: Cardinality) {
		val serialized = when (value) {
			is Cardinality.AtLeast -> "${value.entries}-"
			is Cardinality.AtMost -> "-${value.entries}"
			is Cardinality.Between -> "${value.min}-${value.max}"
			is Cardinality.Exactly -> value.entries.toString()
		}
		encoder.encodeString(serialized)
	}

}
