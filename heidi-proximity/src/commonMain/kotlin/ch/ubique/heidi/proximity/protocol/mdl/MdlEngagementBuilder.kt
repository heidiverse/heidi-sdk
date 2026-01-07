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

import ch.ubique.heidi.proximity.protocol.EngagementBuilder
import ch.ubique.heidi.util.extensions.toCbor
import uniffi.heidi_util_rust.encodeCbor
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.uuid.Uuid

class MdlEngagementBuilder(
    private val verifierName: String,
    private val coseKey: ByteArray,
    private val centralClientUuid: Uuid?,
    private val peripheralServerUuid: Uuid?,
    private val centralClientModeSupported: Boolean,
    private val peripheralServerModeSupported: Boolean,
    private val capabilities: MdlCapabilities? = null,
) : EngagementBuilder {
    @OptIn(ExperimentalEncodingApi::class)
    override fun createQrCodeForEngagement(): String {
        val data = getEngagementBytes()
        return "mdoc:${
            Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT_OPTIONAL)
                .encode(data)
        }"
    }
    fun getEngagementBytes() : ByteArray {
        val deviceEngagement = mutableMapOf(
            0 to "1.1",
            1 to listOf(
                1,
                24 to coseKey.toCbor()
            ),
        )
        //TODO: UBAM make allow to have either/or
        if(centralClientUuid != null && peripheralServerUuid != null) {
            deviceEngagement.put(2, listOf(
                    listOf(
                        2,
                        1,
                        mapOf(
                            0 to peripheralServerModeSupported,
                            1 to centralClientModeSupported,
                            10 to peripheralServerUuid.toByteArray(),
                            11 to centralClientUuid.toByteArray()
                        )
                    )
                )
            )
        }
        capabilities?.let {
            deviceEngagement.put(6, capabilities.getValue())
        }
        return encodeCbor(deviceEngagement.toCbor())
    }
}
