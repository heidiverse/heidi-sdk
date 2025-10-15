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

package ch.ubique.heidi.wallet.credentials.activity

import app.cash.sqldelight.coroutines.asFlow
import app.cash.sqldelight.coroutines.mapToList
import ch.ubique.heidi.credentials.SdJwt
import ch.ubique.heidi.trust.framework.swiss.model.*
import ch.ubique.heidi.util.extensions.toBoolean
import ch.ubique.heidi.util.extensions.toLong
import ch.ubique.heidi.wallet.ActivityEntity
import ch.ubique.heidi.wallet.HeidiDatabase
import ch.ubique.heidi.wallet.credentials.LocalizedKeyValue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.flow.map
import kotlinx.datetime.*
import kotlinx.datetime.format.FormatStringsInDatetimeFormats
import kotlinx.datetime.format.byUnicodePattern
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.koin.core.module.dsl.singleOf
import org.koin.dsl.module
import uniffi.heidi_crypto_rust.parseEncodedJwtPayload
import kotlin.time.Clock.*
import kotlin.time.ExperimentalTime


@OptIn(ExperimentalTime::class)
class ActivityRepository private constructor(
	db: HeidiDatabase,
	val json: Json
) {

	companion object {
		val koinModule = module {
			singleOf(::ActivityRepository)
		}
	}

	private val queries = db.activityQueries

	fun clear() {
		queries.clear()
	}

	fun getAllEntities() = queries.getAll().executeAsList()

	fun fullInsert(
		id: Long?,
		type: ActivityType?,
		content: String,
		baseUrl: String,
		frameworkId: String?,
		identityJwt: String?,
		issuanceJwt: String?,
		verificationJwt: String?,
		isVerified: Long,
		isTrusted: Long,
		insertedAt: Long,
		identityId: Long,
		credentialId: Long,
	) = queries.fullInsert(
		id,
		type,
		content,
		baseUrl,
		frameworkId,
		identityJwt,
		issuanceJwt,
		verificationJwt,
		isVerified,
		isTrusted,
		insertedAt,
		identityId,
		credentialId
	)

	fun insertIssuance(
		baseUrl: String,
		identityJwt: String?,
		issuanceJwt: String?,
		isVerified: Boolean,
		isTrusted: Boolean,
		identityId: Long,
		credentialId: Long,
		frameworkId: String?
	) = queries.insert(
		type = ActivityType.ISSUANCE,
		content = "",
		base_url = baseUrl,
		frameworkId,
		identity_jwt = identityJwt,
		issuance_jwt = issuanceJwt,
		verification_jwt = null,
		is_verified = isVerified.toLong(),
		is_trusted = isTrusted.toLong(),
		identity_id = identityId,
		credential_id = credentialId,
		inserted_at = System.now().toEpochMilliseconds(),
	)

	fun insertVerification(
		content: String,
		identityJwt: String?,
		verificationJwt: String?,
		isVerified: Boolean,
		isTrusted: Boolean,
		identityId: Long,
		credentialId: Long,
		frameworkId: String?,
		baseUrl: String = "",
	) = queries.insert(
		type = ActivityType.PROOF,
		content = content,
		base_url = baseUrl,
		frameworkId,
		identity_jwt = identityJwt,
		issuance_jwt = null,
		verification_jwt = verificationJwt,
		is_verified = isVerified.toLong(),
		is_trusted = isTrusted.toLong(),
		identity_id = identityId,
		credential_id = credentialId,
		inserted_at = System.now().toEpochMilliseconds(),
	)

	fun getById(id: Long) = queries.getById(id).executeAsOneOrNull()?.toModel(json)

	fun getByIdentityId(identityId: Long) =
		queries.getByIdentityId(identityId).executeAsList().map { it.toModel(json) }

	fun getActivities(credentialId: Long) =
		queries.getByCredentialId(credentialId).executeAsList().map { it.toModel(json) }

	fun getActivities(credentialIds: List<Long>) =
		queries.getByCredentialIds(credentialIds).executeAsList().map { it.toModel(json) }

	fun getAll() = queries.getAll().executeAsList().map { it.toModel(json) }

	fun getAllAsFlow() = queries.getAll()
		.asFlow()
		.mapToList(Dispatchers.IO)
		.map { entities ->
			entities.map { it.toModel(json) }
		}

	@OptIn(FormatStringsInDatetimeFormats::class)
	private fun ActivityEntity.toModel(json: Json): ActivityUiModel {
		val identity = identity_jwt?.let {
			runCatching { SdJwt.parse(it) }.getOrNull()?.innerJwt?.claims?.let {
				json.encodeToString(
					it
				)
			} ?: parseEncodedJwtPayload(it)
		}?.let {
			kotlin.runCatching { json.decodeFromString<TrustedIdentity>(it) }.getOrNull()
				?: kotlin.runCatching { json.decodeFromString<TrustedIdentityV2>(it) }.getOrNull()
					?.let { TrustedIdentity.fromV2(it) }
		}
		return if (type == ActivityType.PROOF) {
			val values = json.decodeFromString<List<LocalizedKeyValue>>(content)
			ActivityUiModel.Proof(
				id = id,
				frameworkId = frameworkId,
				type = type,
				insertedAt = Instant.fromEpochMilliseconds(inserted_at)
					.toLocalDateTime(TimeZone.currentSystemDefault())
					.format(LocalDateTime.Format { byUnicodePattern("dd.MM.yyyy HH:mm") }),
				values = values,
				verificationTrustData = TrustData.Verification(
					baseUrl = base_url,
					identity = identity,
					identityJwt = identity_jwt,
					verification = verification_jwt?.let { parseEncodedJwtPayload(it) }
						?.let { runCatching { json.decodeFromString<TrustedVerification>(it) }.getOrNull() },
					verificationJwt = verification_jwt,
					isVerified = is_verified.toBoolean(),
					isTrusted = is_trusted.toBoolean()
				)
			)
		} else {
			ActivityUiModel.Issuance(
				id = id,
				type = requireNotNull(type),
				insertedAt = Instant.fromEpochMilliseconds(inserted_at)
					.toLocalDateTime(TimeZone.currentSystemDefault())
					.format(LocalDateTime.Format { byUnicodePattern("dd.MM.yyyy HH:mm") }),
				frameworkId = frameworkId,
				issuanceTrustData = TrustData.Issuance(
					baseUrl = base_url,
					identity = identity,
					identityJwt = identity_jwt,
					issuance = issuance_jwt?.let { parseEncodedJwtPayload(it) }
						?.let { runCatching { json.decodeFromString<TrustedIssuance>(it) }.getOrNull() },
					issuanceJwt = issuance_jwt,
					isTrusted = is_trusted.toBoolean(),
					isVerified = is_verified.toBoolean()
				)
			)
		}
	}
}
