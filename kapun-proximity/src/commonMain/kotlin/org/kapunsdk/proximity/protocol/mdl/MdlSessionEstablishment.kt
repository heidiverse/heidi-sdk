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

package org.kapunsdk.proximity.protocol.mdl

import org.kapunsdk.util.extensions.asBoolean
import org.kapunsdk.util.extensions.asBytes
import org.kapunsdk.util.extensions.asTag
import org.kapunsdk.util.extensions.get
import org.kapunsdk.util.extensions.toCbor
import uniffi.kapun_util_rust.Value
import uniffi.kapun_util_rust.decodeCbor
import uniffi.kapun_util_rust.encodeCbor

data class MdlSessionEstablishment(val eReaderKey: Value, val data: ByteArray, val dcApiSelected: Boolean?) {
    companion object {
        fun fromCbor(data: ByteArray) : MdlSessionEstablishment? {
            val decoded = kotlin.runCatching { decodeCbor(data) }.getOrNull() ?: return null
            val eReaderKey = decoded.get("eReaderKey").asTag() ?: return null
            val d = decoded.get("data").asBytes() ?: return null
            val dcApiSelected = decoded.get("dcApiSelected").asBoolean() ?: false
            return MdlSessionEstablishment(eReaderKey, d, dcApiSelected)
        }
    }
    fun asCbor() : ByteArray {
        val isDcApi = dcApiSelected ?: false
        return encodeCbor(mapOf(
            "eReaderKey" to eReaderKey,
            "data" to data,
            "dcApiSelected" to isDcApi
        ).toCbor())
    }
}
