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

package ch.ubique.heidi.wallet.network

import io.ktor.client.engine.HttpClientEngineConfig
import io.ktor.client.engine.ProxyBuilder
import io.ktor.client.engine.http

actual fun HttpClientEngineConfig.configureSystemProxy() {
	getProxySettings()?.let  {
		this.proxy = ProxyBuilder.http("http://${it.first}:${it.second}")
	}
}

private fun getProxySettings(): Pair<String, UShort>? {
	val systemProxyHost = System.getProperty("http.proxyHost")
	val systemProxyPort = System.getProperty("http.proxyPort")?.toUShortOrNull()
	return systemProxyPort?.let {  port ->
		systemProxyHost?.let {  host ->
			Pair(host, port)
		}
	}
}
