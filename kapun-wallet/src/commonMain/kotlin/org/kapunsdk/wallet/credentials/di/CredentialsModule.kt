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

package org.kapunsdk.wallet.credentials.di

import org.kapunsdk.wallet.credentials.ViewModelFactory
import org.kapunsdk.wallet.credentials.activity.ActivityRepository
import org.kapunsdk.wallet.credentials.credential.CredentialStore
import org.kapunsdk.wallet.credentials.credential.CredentialsController
import org.kapunsdk.wallet.credentials.credential.CredentialsRepository
import org.kapunsdk.wallet.credentials.credential.DeferredCredentialsRepository
import org.kapunsdk.wallet.credentials.identity.IdentityRepository
import org.kapunsdk.wallet.credentials.issuer.IssuerRepository
import org.kapunsdk.wallet.credentials.mapping.FallbackIdentityMapper
import org.kapunsdk.wallet.credentials.mapping.OcaIdentityMapper
import org.kapunsdk.wallet.credentials.oca.OcaRepository
import org.kapunsdk.wallet.credentials.oca.networking.OcaServiceController
import org.kapunsdk.wallet.credentials.signeddocument.SignedDocumentsController
import org.kapunsdk.wallet.credentials.signeddocument.SignedDocumentsRepository
import org.koin.dsl.module

internal fun credentialsModule() = module {
	includes(
		ActivityRepository.koinModule,
		CredentialsController.koinModule,
		CredentialsRepository.koinModule,
		DeferredCredentialsRepository.koinModule,
		IdentityRepository.koinModule,
		IssuerRepository.koinModule,
		OcaIdentityMapper.koinModule,
		FallbackIdentityMapper.koinModule,
		OcaRepository.koinModule,
		OcaServiceController.koinModule,
		CredentialStore.koinModule,
		ViewModelFactory.koinModule,
		SignedDocumentsRepository.koinModule,
		SignedDocumentsController.koinModule,
	)
}
