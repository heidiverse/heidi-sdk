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

package ch.ubique.heidi.trust.framework.swiss.model

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonNames

@Serializable
class TrustedIdentity(
	val vct: String?,
	val iss: String?,
	val sub: String?,
	val iat: Long?,
	val nbf: Long?,
	val exp: Long?,
	val status: String?,
	@JsonNames("orgName")
	val entityName: Map<String, String>,
	val registryIds: List<Registry>?,
	val logoUri: Map<String, String>?,
	val prefLang: String?
)

fun TrustedIdentity.Companion.fromV2(v2: TrustedIdentityV2) : TrustedIdentity {
	return TrustedIdentity(
        vct = v2.vct,
        iss = v2.iss,
        sub = v2.sub,
        iat = v2.iat,
        nbf = v2.nbf,
        exp = v2.exp,
        status = null,
        entityName = v2.entityName,
        registryIds = null,
        logoUri = v2.logoUri,
        prefLang = v2.prefLang,
    )
}

@Serializable
class Registry(
	val type: String,
	val value: String,
)

@Serializable
class TrustedIdentityV2(
	val vct: String,
	val iss: String,
	val sub: String,
	val iat: Long,
	val nbf: Long?,
	val exp: Long?,
	@JsonNames("orgName")
	val entityName: Map<String, String>,
	val logoUri: Map<String, String>?,
	val prefLang: String?
)
