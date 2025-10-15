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

package ch.ubique.heidi.wallet.di

import ch.ubique.heidi.wallet.credentials.di.credentialsModule
import ch.ubique.heidi.wallet.crypto.di.cryptoModule
import ch.ubique.heidi.wallet.database.di.databaseModule
import ch.ubique.heidi.wallet.keyvalue.di.keyValueModule
import ch.ubique.heidi.wallet.network.di.networkModule
import ch.ubique.heidi.wallet.process.legacy.di.processesModule
import ch.ubique.heidi.wallet.resources.di.resourcesModule
import org.koin.core.KoinApplication

fun KoinApplication.heidiWalletModules() {
	modules(
		cryptoModule(),
		databaseModule(),
		networkModule(),
		keyValueModule(),
		resourcesModule(),
		credentialsModule(),
		processesModule(),
	)
}
