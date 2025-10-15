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

package ch.ubique.heidi.trust.revocation

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonNames
import uniffi.heidi_issuance_rust.StatusList
import uniffi.heidi_util_rust.deflateString

//@Serializable
//data class StatusList @OptIn(ExperimentalSerializationApi::class) constructor(val sub: String, @JsonNames("status_list") val statusList: StatusList) {
//    @Serializable
//    data class  StatusList(val lst: String, val bits: Int) {
//        fun isRevoked(index: Int) : Boolean {
//            return kotlin.runCatching {
//                val decompressed = deflateString(lst)
//                if(index/8 >decompressed.size) {
//                    return true
//                }
//                val byteNumber = index / 8
//                val bitIndex = index % 8
//                val statusByte = decompressed[byteNumber].toUByte()
//                val statusBit = statusByte.and((1.shl(bitIndex)).toUByte())
//                statusBit == 1.shl(bitIndex).toUByte()
//            }.getOrNull() ?: true
//        }
//    }
//}

fun StatusList.isRevoked(index: Int) : Boolean {
        return kotlin.runCatching {
        val decompressed = deflateString(lst)
        if(index/8 >decompressed.size) {
            return true
        }
        val byteNumber = index / 8
        val bitIndex = index % 8
        val statusByte = decompressed[byteNumber].toUByte()
        val statusBit = statusByte.and((1.shl(bitIndex)).toUByte())
        statusBit == 1.shl(bitIndex).toUByte()
    }.getOrNull() ?: true
}

