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

package ch.ubique.heidi.trust.framework.oid4vp

import ch.ubique.heidi.trust.framework.DidWebTrustAnchorProvider
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.URLBuilder
import io.ktor.http.Url
import io.ktor.http.appendPathSegments
import io.ktor.http.takeFrom
import kotlinx.serialization.json.Json
import uniffi.heidi_crypto_rust.getKidFromJwt
import uniffi.heidi_crypto_rust.parseDidVerificationDocument
import uniffi.heidi_crypto_rust.validateJwtWithDidDocument
import uniffi.heidi_util_rust.Value

class StaticDidWebTrustAnchorProvider : DidWebTrustAnchorProvider {
    private val json = Json { ignoreUnknownKeys = true }
    private val httpClient = HttpClient()
    private val trustedDomains = listOf<String>("itb.ilabs.ai")

    private fun resolveUrl(kid: String): Url? = runCatching {
        if (!kid.startsWith("did:web")) {
            return null
        }
        val kid = kid.removePrefix("did:web:")
            .replace(':', '/')
            .replace("%3A", ":", ignoreCase = true)

        URLBuilder()
            .takeFrom("https://$kid")
            .apply {
                if (pathSegments.none { it.isNotBlank() }) {
                    appendPathSegments(".well-known")
                }
                appendPathSegments("did.json")
            }
            .build()
    }.getOrNull()

    override fun isTrusted(kid: String): Boolean {
        val url = resolveUrl(kid) ?: return false
        return trustedDomains.contains(url.host)
    }

    override suspend fun verifyJwt(jwt: String): Boolean {
        val kid = getKidFromJwt(jwt) ?: return false
        val url = resolveUrl(kid) ?: return false;

        val resp = httpClient.get(url)
            .bodyAsText()

        val doc = parseDidVerificationDocument(json.decodeFromString<Value>(resp))
            ?: return false

        return validateJwtWithDidDocument(jwt, doc, validateAud = false)
    }

}
