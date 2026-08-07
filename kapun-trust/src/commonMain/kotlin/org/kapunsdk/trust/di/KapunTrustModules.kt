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

package org.kapunsdk.trust.di

import org.kapunsdk.trust.framework.swiss.SwissTrustRepository
import org.kapunsdk.trust.framework.swiss.SwissTrustService
import org.kapunsdk.trust.networking.di.jsonModule
import org.kapunsdk.trust.networking.di.networkModule
import org.kapunsdk.trust.revocation.RevocationCache
import org.koin.core.KoinApplication

internal fun KoinApplication.trustModules() {
	modules(
		jsonModule(),
		networkModule(),
		SwissTrustService.koinModule,
		SwissTrustRepository.koinModule,
		RevocationCache.koinModule
	)
}
