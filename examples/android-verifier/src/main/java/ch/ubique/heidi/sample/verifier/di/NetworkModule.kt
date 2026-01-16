/* Copyright 2024 Ubique Innovation AG

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
package ch.ubique.heidi.sample.verifier.di


import ch.ubique.heidi.sample.verifier.feature.network.createVerifierService
import de.jensklingenberg.ktorfit.Ktorfit
import de.jensklingenberg.ktorfit.converter.FlowConverterFactory
import de.jensklingenberg.ktorfit.converter.ResponseConverterFactory
import de.jensklingenberg.ktorfit.ktorfitBuilder
import io.ktor.client.HttpClient
import io.ktor.client.engine.okhttp.OkHttp
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.serialization.kotlinx.json.json
import kotlinx.serialization.json.Json
import org.koin.dsl.module

val networkModule = module {

	single {
		val ktorfit: Ktorfit = get()
		ktorfit.createVerifierService()
	}

	single {
		val httpClient: HttpClient = get()
		ktorfitBuilder {

			httpClient(httpClient)
			converterFactories(
				FlowConverterFactory(),
				ResponseConverterFactory()
			)
		}.build()
	}

	single {
		HttpClient(OkHttp) {
			expectSuccess = true
			install(ContentNegotiation) {
				json(
					Json {
						isLenient = true
						ignoreUnknownKeys = true
						explicitNulls = false
					}
				)
			}
		}
	}
}
