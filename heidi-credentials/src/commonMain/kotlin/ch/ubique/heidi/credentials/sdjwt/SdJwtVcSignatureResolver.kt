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

package ch.ubique.heidi.credentials.sdjwt

import ch.ubique.heidi.util.extensions.asString
import ch.ubique.heidi.util.extensions.get
import io.ktor.http.URLBuilder
import io.ktor.http.appendPathSegments
import io.ktor.http.path
import io.ktor.http.takeFrom
import kotlinx.serialization.json.Json
import uniffi.heidi_crypto_rust.parseEncodedJwtHeader
import uniffi.heidi_crypto_rust.parseEncodedJwtPayload
import uniffi.heidi_util_rust.Value

object SdJwtVcSignatureResolver {

    private fun retrievePkUsingJwtVcIssuerMetadata(jwt: String): Value? {
        val kid = parseEncodedJwtHeader(jwt)
            ?.let { Json.decodeFromString<Value>(it)["kid"].asString() }
            ?: return null

        val payload = parseEncodedJwtPayload(jwt)
            ?.let { Json.decodeFromString<Value>(it) }
            ?: return null

        val iss = payload["iss"].asString()
            ?: return null

        val jwks = runCatching {
            val url = URLBuilder()
                .takeFrom(iss)
                .apply {
                    val path = arrayOf(".well-known", "jwt-vc-issuer") + encodedPathSegments
                    path(*path)
                }
                .build()
        }

        // TODO
        return null
    }

    private fun retrievePkUsingX509Cert(): Value? {
        // TODO
        return null
    }

    private fun retrievePkUsingDidWeb(): Value? {
        // TODO
        return null
    }

    fun isSignatureValid(jwt: String): Boolean {
        val pk = retrievePkUsingJwtVcIssuerMetadata(jwt)
            ?: retrievePkUsingX509Cert()
            ?: retrievePkUsingDidWeb()
            ?: return false

        // TODO: "Verify the jwt using the public key"

        return false
    }
}
