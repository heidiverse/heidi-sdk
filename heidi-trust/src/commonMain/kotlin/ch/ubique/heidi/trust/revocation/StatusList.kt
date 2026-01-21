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

import uniffi.heidi_issuance_rust.StatusList
import uniffi.heidi_util_rust.deflateString


const val VALID = 0
const val REVOKED = 1
const val SUSPENDED = 2

fun StatusList.isRevoked(index: Int) : Boolean {
        return kotlin.runCatching {
                val status = this.getStatus(index) ?: return false
                status == REVOKED.toByte()
        }.getOrNull() ?: true
}

fun StatusList.getStatus(index: Int) : Byte? {
        return kotlin.runCatching {
                val decompressed = deflateString(lst)
                val entrySize = (8U / this.bits).toByte()
                if(index/entrySize >decompressed.size) {
                        return null
                }
                val byteNumber = index / entrySize
                val bitIndex = index % entrySize
                val statusByte = decompressed[byteNumber].toUByte()
                val statusMask = 255.shr(8 - this.bits.toByte())
                val statusBits = statusByte.and(
                        statusMask.shl(bitIndex * this.bits.toInt()).toUByte())
                        .toInt().shr(bitIndex * this.bits.toInt())
                statusBits.toByte()
        }.getOrNull()
}

fun StatusList.isSuspended(index: Int) : Boolean {
        return kotlin.runCatching {
                val status = this.getStatus(index) ?: return false
                status == SUSPENDED.toByte()
        }.getOrNull() ?: true
}

