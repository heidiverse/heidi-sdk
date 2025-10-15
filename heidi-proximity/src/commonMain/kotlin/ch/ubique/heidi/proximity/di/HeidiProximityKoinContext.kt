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
package ch.ubique.heidi.proximity.di

import ch.ubique.heidi.proximity.ble.bleModule
import ch.ubique.heidi.proximity.protocol.mdl.iso180135Module
import ch.ubique.heidi.proximity.protocol.openid4vp.openId4vpModule
import org.koin.core.Koin
import org.koin.core.KoinApplication
import org.koin.core.context.startKoin
import org.koin.core.module.Module
import org.koin.dsl.koinApplication

fun KoinApplication.proximityModules() {
	modules(
		bleModule,
		openId4vpModule,
		iso180135Module
	)
}

internal object HeidiProximityKoinContext {

	private lateinit var koinApp: KoinApplication
	lateinit var koin: Koin

	fun initialize(addendum: KoinApplication.() -> Unit = {}) {
		koinApp = koinApplication {
			proximityModules()
			addendum()
		}
		koin = koinApp.koin
	}
}

@Suppress("unused")
fun initKoiniOS() {
	startKoin {
		proximityModules()
	}
}
