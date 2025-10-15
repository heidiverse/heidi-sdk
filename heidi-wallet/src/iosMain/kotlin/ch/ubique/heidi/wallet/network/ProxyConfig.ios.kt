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
import io.ktor.client.engine.darwin.DarwinClientEngineConfig
import kotlinx.cinterop.ExperimentalForeignApi
import platform.CFNetwork.*
import platform.CoreFoundation.CFStringCreateWithCString
import platform.CoreFoundation.CFURLCreateWithString
import platform.Foundation.CFBridgingRelease
import platform.Foundation.NSNumber

actual fun HttpClientEngineConfig.configureSystemProxy() {
	getSystemProxy()?.let {
		if(this is DarwinClientEngineConfig) {
			this.configureSession {
				setConnectionProxyDictionary(mapOf(
					"HTTPEnable" to 1,
					"HTTPSProxy" to it.first,
					"HTTPSPort" to it.second,
					"HTTPProxy" to it.first,
					"HTTPPort" to it.first
				))
			}
		}
	}
}

@OptIn(ExperimentalForeignApi::class)
private fun getSystemProxy() : Pair<String, UShort>? {
	return CFNetworkCopySystemProxySettings()?.let {
		val cfUrl = CFStringCreateWithCString(null, "http://example.com", 0U)
		val url = CFURLCreateWithString(null, cfUrl, null)
		val proxiesNullable : List<Map<String, Any>>? = CFNetworkCopyProxiesForURL(url, it)?.let {
			CFBridgingRelease(it) as List<Map<String, Any>>?
		}  ?: return null
		val proxies = proxiesNullable ?: return null
		val kCFProxyTypeKeyKotlin = CFBridgingRelease(kCFProxyTypeKey) as String
		val kCFProxyHostNameKeyKotlin = CFBridgingRelease(kCFProxyHostNameKey) as String
		val kCFProxyPortNumberKeyKotlin = CFBridgingRelease(kCFProxyPortNumberKey) as String

		val kCFProxyTypeValueKotlin = CFBridgingRelease(kCFProxyTypeHTTP) as String
		val proxyType = proxies.firstOrNull()?.let { proxy -> proxy[kCFProxyTypeKeyKotlin] } as String? ?: return null
		if(proxyType != kCFProxyTypeValueKotlin) {
			return null
		}
		val host = proxies.firstOrNull()?.let { proxy -> proxy[kCFProxyHostNameKeyKotlin]  } as String? ?: return null
		val port = proxies.firstOrNull()?.let { proxy -> proxy[kCFProxyPortNumberKeyKotlin] } as NSNumber? ?: return null
		print("http://${host}:${port}")

		Pair(host, port.unsignedShortValue)
	}
}
