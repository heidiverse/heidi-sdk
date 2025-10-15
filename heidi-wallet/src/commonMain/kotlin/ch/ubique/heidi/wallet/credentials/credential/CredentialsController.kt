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

package ch.ubique.heidi.wallet.credentials.credential

import ch.ubique.heidi.credentials.models.credential.CredentialType
import ch.ubique.heidi.trust.revocation.RevocationCheck
import ch.ubique.heidi.wallet.credentials.ViewModelFactory
import ch.ubique.heidi.wallet.credentials.activity.ActivityRepository
import ch.ubique.heidi.wallet.credentials.identity.IdentityRepository
import ch.ubique.heidi.wallet.credentials.identity.IdentityUiModel
import ch.ubique.heidi.wallet.extensions.toModel
import ch.ubique.heidi.wallet.keyvalue.KeyValueEntry
import ch.ubique.heidi.wallet.keyvalue.KeyValueRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.zip
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json.Default.parseToJsonElement
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.koin.dsl.module
import kotlin.math.min

class CredentialsController private constructor(
	private val credentialsRepository: CredentialsRepository,
    private val deferredCredentialsRepository: DeferredCredentialsRepository,
	private val identityRepository: IdentityRepository,
	private val activityRepository: ActivityRepository,
	private val viewModelFactory: ViewModelFactory,
	private val keyValueRepository: KeyValueRepository,
	private val scope: CoroutineScope,
) {
	companion object {
		val koinModule = module {
			factory { (scope: CoroutineScope) ->
				CredentialsController(
					get(), get(), get(), get(), get(), get(), scope
				)
			}
		}
	}

	private val asyncJobs = mutableMapOf<String, Job>()
	fun resetState() {
		asyncJobs.values.forEach { it.cancel() }
	}

	private fun launchSingleJob(label: String, block: suspend () -> Unit) {
		asyncJobs[label]?.cancel()
		asyncJobs[label] = scope.launch(Dispatchers.IO) {
			block()
		}
	}

    fun getPids() = identityRepository.getPids()
    fun getNonPids(withIssuerData: Boolean = true) = identityRepository.getNonPids(withIssuerData)
    fun getNonPidCount() = identityRepository.getNonPidCount()
    fun getDeferred() = deferredCredentialsRepository.getAll()
    fun getIdentityForTransactionId(transactionId: String) = deferredCredentialsRepository.getIdentityForTransactionId(transactionId)
    fun getDeferredForTransactionId(transactionId: String) = deferredCredentialsRepository.getForTransactionId(transactionId)
    val revocationCheck = RevocationCheck()
    fun getIdentityByName(identityName: String) =
        identityRepository.getByName(identityName).map { it?.let { viewModelFactory.getIdentityUiModel(it, revocationCheck) } }

	fun getIdentityByActivityId(activityId: Long) =
		identityRepository.getByActivityId(activityId)?.let { viewModelFactory.getIdentityUiModel(it, revocationCheck) }

	fun getAllIdentityUiModels() = identityRepository.getAllAsFlow().map {
		it.mapNotNull { identity ->
			viewModelFactory.getIdentityUiModel(identity, revocationCheck)
		}
	}
	fun getAllIdentityAndDeferredUiModels() = combine(deferredCredentialsRepository.getAllAsFlow().map { def ->
		def.map { defId ->
			viewModelFactory.getIdentityUiModel(defId)
		}
	}, identityRepository.getAllAsFlow().map{
		it.mapNotNull { identity ->
			viewModelFactory.getIdentityUiModel(identity, revocationCheck)
		}
	}) { deferredIds, issuedIds ->
		deferredIds + issuedIds
	}

	fun getAllCredentialsFlow() = credentialsRepository.getAllUnusedFlow()

	fun removeIdentityById(identityId: Long) {
		identityRepository.removeById(identityId)
	}

	fun removeIdentityByName(identityName: String) {
		identityRepository.removeByName(identityName)
	}

	fun getAllActivities() = activityRepository.getAllAsFlow()

	fun getActivityById(id: Long) = activityRepository.getById(id)

	fun setCredentialsLimit(number: Int?) {
		keyValueRepository.setFor(KeyValueEntry.MAX_CREDENTIALS, number?.toString())
	}

    fun anonymizeElement(element: JsonElement) : JsonElement {
        return when(element) {
            is JsonArray -> {
                return JsonArray(element.jsonArray.subList(fromIndex = 0, toIndex = min(element.jsonArray.size, 10)).map {
                    anonymizeElement(it)
                })
            }
            is JsonObject -> {
                return JsonObject(element.jsonObject.mapValues {
                    anonymizeElement(it.value)
                })
            }
            JsonNull -> JsonNull
            else -> {
                val primitive = element.jsonPrimitive
                val value = element.jsonPrimitive.contentOrNull ?: primitive.toString()
                val first = value.firstOrNull()
                val last = value.lastOrNull()
                return if(value.count() <= 1) {
                    JsonPrimitive("$first")
                } else {
                    JsonPrimitive("$first****$last")
                }

            }
        }
    }
    suspend fun publishToDCApi() : List<JsonElement> {
//		return emptyList()
		val models =
			getAllIdentityUiModels().first()
		// Can add more here
		val keysToRemove = setOf("vct")
		val myCredentialList = mutableListOf<JsonElement>()
		for (model in models) {
			if (model !is IdentityUiModel.IdentityUiCredentialModel) {
				continue
			}
			val insertedFormats = mutableListOf<CredentialType>()
			for (cred in model.credentials) {
				if(insertedFormats.contains(cred.credentialType)) {
					continue
				}
				val credential = model.getCredentialUiModelForSingle(cred, viewModelFactory)
				insertedFormats.add(cred.credentialType)
				val credentialJson: JsonObject =
					parseToJsonElement(credential.jsonPayload.orEmpty()).jsonObject
				val myCred =
					buildJsonObject {
						// Copy over entries except those in keysToRemove
						put("paths", buildJsonObject {
							credentialJson.forEach { (key, value) ->
								if (key !in keysToRemove) {
									put(key, anonymizeElement(value))
								}
							}
						})
						put("credential_format", if (credential.type == CredentialType.SdJwt) {"dc+sd-jwt"} else {"mso_mdoc"})
						put("document_type", model.docType)
						// Add new fields
						put(
							"id",
							JsonPrimitive(credential.id.toString())
						)
						put("title", JsonPrimitive(model.title))
						put("subtitle", JsonPrimitive(model.subtitle))
					}                // Add to our list
				myCredentialList.add(myCred)
			}
		}
		// Now we can filter out duplicate entries if we want to.
		// And then the thingy should be ready to insert into the dc-api wasm thingy.
		//  wasm_insert(myCredentialList, somethingSmartHere)
		return myCredentialList
    }
	fun getCredentialsLimit() = keyValueRepository.getForFlow(KeyValueEntry.MAX_CREDENTIALS).map { it?.toIntOrNull() }
		.stateIn(scope, SharingStarted.WhileSubscribed(), null)

}
