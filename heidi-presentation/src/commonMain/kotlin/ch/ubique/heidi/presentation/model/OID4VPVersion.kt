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

package ch.ubique.heidi.presentation.model

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Serializable(with = Oid4vpVersionSerializer::class)
enum class OID4VPVersion(val version: Int) {
    DRAFT_21(21), DRAFT_24(24), DRAFT_26(26), DRAFT_28(28), VERSION_ONE_DOT_ZERO(100);

    companion object Companion {
        fun fromVersion(version: Int): OID4VPVersion {
            return values().find { it.version == version }
                ?: throw IllegalArgumentException("Unknown oid4vp version: $version")
        }
    }
}

class Oid4vpVersionSerializer : KSerializer<OID4VPVersion> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Oid4vpVersion", PrimitiveKind.INT)

    override fun serialize(encoder: Encoder, value: OID4VPVersion) {
        encoder.encodeInt(value.version)
    }

    override fun deserialize(decoder: Decoder): OID4VPVersion {
        val version = decoder.decodeInt()
        return OID4VPVersion.fromVersion(version)
    }
}
