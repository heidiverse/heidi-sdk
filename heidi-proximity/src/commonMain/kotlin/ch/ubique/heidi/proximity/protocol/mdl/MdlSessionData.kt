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

package ch.ubique.heidi.proximity.protocol.mdl

import ch.ubique.heidi.util.extensions.asBytes
import ch.ubique.heidi.util.extensions.asLong
import ch.ubique.heidi.util.extensions.get
import uniffi.heidi_util_rust.decodeCbor

data class MdlSessionData(val data: ByteArray?, val status : Long?) {
    companion object {
        fun fromCbor(data: ByteArray) : MdlSessionData? {
            val decoded = runCatching { decodeCbor(data) }.getOrNull() ?: return null
            val data = decoded.get("data").asBytes()
            val status = decoded.get("status").asLong()
            if(status == null && data == null) {
                return null
            }
            return MdlSessionData(data, status)
        }
    }
}
