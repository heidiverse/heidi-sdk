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

package ch.ubique.heidi.wallet.credentials.di

import ch.ubique.heidi.wallet.credentials.ViewModelFactory
import ch.ubique.heidi.wallet.credentials.activity.ActivityRepository
import ch.ubique.heidi.wallet.credentials.credential.CredentialStore
import ch.ubique.heidi.wallet.credentials.credential.CredentialsController
import ch.ubique.heidi.wallet.credentials.credential.CredentialsRepository
import ch.ubique.heidi.wallet.credentials.credential.DeferredCredentialsRepository
import ch.ubique.heidi.wallet.credentials.identity.IdentityRepository
import ch.ubique.heidi.wallet.credentials.issuer.IssuerRepository
import ch.ubique.heidi.wallet.credentials.mapping.FallbackIdentityMapper
import ch.ubique.heidi.wallet.credentials.mapping.OcaIdentityMapper
import ch.ubique.heidi.wallet.credentials.oca.OcaRepository
import ch.ubique.heidi.wallet.credentials.oca.networking.OcaServiceController
import ch.ubique.heidi.wallet.credentials.signeddocument.SignedDocumentsController
import ch.ubique.heidi.wallet.credentials.signeddocument.SignedDocumentsRepository
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
