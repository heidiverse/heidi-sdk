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

package ch.ubique.heidi.trust.framework.swiss

import ch.ubique.heidi.trust.didtdw.DidTdwResolver
import ch.ubique.heidi.trust.framework.swiss.dto.IssuanceTrustStatementsDto
import ch.ubique.heidi.trust.framework.swiss.dto.VerificationTrustStatementsDto
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.request.get
import io.ktor.client.request.headers
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.URLBuilder
import io.ktor.http.appendPathSegments
import kotlinx.serialization.json.Json
import org.koin.core.module.dsl.singleOf
import org.koin.dsl.module
import uniffi.heidi_util_rust.Value

internal class SwissTrustService(
	private val httpClient: HttpClient,
) {

	companion object {
		val koinModule = module {
			singleOf(::SwissTrustService)
		}

		private const val WELL_KNOWN_PATH = "/.well-known"
		private const val TRUST_STATEMENT_PATH = "$WELL_KNOWN_PATH/trust-statement"
		private const val TRUST_API_BASE_URL = "https://trust-reg.trust-infra.swiyu-int.admin.ch"
		private const val TRUST_API_PATH = "/api/v1/truststatements"
		private val DID_REGEX = Regex("did:(tdw|webvh):(?<integrity>.+?):(?<domain>([A-z-_0-9.]+))(:(?<path>.+)?)")
	}

	suspend fun getIssuanceTrustStatements(baseUrl: String): IssuanceTrustStatementsDto {
		val url = URLBuilder(baseUrl).apply {
			appendPathSegments(TRUST_STATEMENT_PATH)
		}.build()

		return httpClient.get(url).body<IssuanceTrustStatementsDto>()
	}

	suspend fun getVerificationTrustStatements(baseUrl: String): VerificationTrustStatementsDto {
		val url = URLBuilder(baseUrl).apply {
			appendPathSegments(TRUST_STATEMENT_PATH)
		}.build()

		return httpClient.get(url).body<VerificationTrustStatementsDto>()
	}

	suspend fun getTrustFromDid(did: String) : List<String> {
		return kotlin.runCatching {
			val url = URLBuilder(TRUST_API_BASE_URL).apply {
				appendPathSegments(TRUST_API_PATH)
				appendPathSegments(did, encodeSlash = true)
			}.build()

			val result = httpClient.get(url).bodyAsText()
			return Json {  }.decodeFromString(result)
		}.getOrDefault(emptyList())
	}
	suspend fun getDidDocument(did: String): DidTdwResolver.Entry? {
		val matches = DID_REGEX.matchEntire(did) ?: return null
		val url = matches.groups["domain"]?.value ?: return null
		val path = matches.groups["path"]?.value?.replace(":", "/")?.let {
			"$it/did.jsonl"
		}
		val keyUrl = URLBuilder("https://$url").apply {
			if(path!=null){
				appendPathSegments(path)
			} else {
				appendPathSegments(".well-known/did.jsonl")
			}
		}.build()
		val res = httpClient.get(keyUrl) {
			headers {
				append(HttpHeaders.Accept, "application/jsonl+json")
			}
		}.body<String>()

		return runCatching {
			val jsonl = res.split('\n').toList()
			val resolver = DidTdwResolver.parse(jsonl)
			resolver.resolveLatest()
		}.getOrNull()
	}

}
