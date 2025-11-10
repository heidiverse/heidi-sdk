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

package ch.ubique.heidi.wallet.environment

object EnvironmentController {

	private var environment = EnvironmentType.DEV

	fun setEnvironment(environment: EnvironmentType) {
		EnvironmentController.environment = environment
	}

	fun getHsmBackendUrl() = when (environment) {
		EnvironmentType.DEV -> "https://sprind-eudi-hsm-connector-ws-dev.ubique.ch/v1"
		EnvironmentType.PROD -> "https://sprind-eudi-hsm-connector-ws-prod.ubique.ch/v1"
	}

	fun getHeidiUrl() = when (environment) {
		EnvironmentType.DEV -> "https://heidi-dev.ubique.ch"
		EnvironmentType.PROD -> "https://heidi.ubique.ch"
	}

	fun getHeidiBackupUrl() = when (environment) {
		EnvironmentType.DEV -> "https://sprind-eudi-backup-ws-dev.ubique.ch"
		EnvironmentType.PROD -> "https://sprind-eudi-backup-ws-prod.ubique.ch"
	}

	fun getIssuerBackendUrl() = when (environment) {
		EnvironmentType.DEV -> "https://ssi-issuer-backend-ws-dev.ubique.ch"
		EnvironmentType.PROD -> "https://ssi-issuer-backend-ws-prod.ubique.ch"
	}

}
