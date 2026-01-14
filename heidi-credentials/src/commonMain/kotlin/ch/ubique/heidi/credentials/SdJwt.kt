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

package ch.ubique.heidi.credentials

import ch.ubique.heidi.credentials.sdjwt.SdJwtVcMetadata
import ch.ubique.heidi.credentials.sdjwt.SdJwtVcSignatureResolver
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import uniffi.heidi_crypto_rust.base64UrlEncode
import uniffi.heidi_crypto_rust.sha256Rs
import uniffi.heidi_credentials_rust.*
import uniffi.heidi_util_rust.Value
import kotlin.collections.set
import ch.ubique.heidi.util.extensions.*
import io.ktor.client.request.invoke

sealed interface SdJwtErrors {
    data class InvalidFormat(val msg: String) : SdJwtErrors, Throwable(msg)
    data class InvalidDisclosurePath(val path: List<PointerPart>): SdJwtErrors, Throwable(message = "Path: $path invalid")
}
val UNDISCLOSABLE_CLAIMS : List<ClaimsPointer>  = listOf(
    listOf("vct").toClaimsPointer()!!,
    listOf("iss").toClaimsPointer()!!,
    listOf("nbf").toClaimsPointer()!!,
    listOf("iat").toClaimsPointer()!!,
    listOf("exp").toClaimsPointer()!!
)
data class SdjwtDisclosure(val disclosedObject: Value, val disclosure: List<String>)
sealed interface IssuanceError {
    data class ElementNotDisclosable(val parent: Value, val paths: List<ClaimsPointer>) : IssuanceError, Throwable("$parent cannot disclose ${paths.joinToString(",")}")
    data class DisclosurePathNotResolved(val path: ClaimsPointer) : IssuanceError, Throwable("Slicing does not make sense: $path")
    data class KeyShouldBeString(val path: ClaimsPointer) : IssuanceError, Throwable("Key should be a string $path")
    data class ArrayMustRevealAll(val path: List<ClaimsPointer>) : IssuanceError, Throwable("We must disclose an array in its full: ${path.joinToString(",")}")
}
fun createDisclosureForObject(claims: Value.Object, objectDisclosures: List<ClaimsPointer>, currentDepth: Int, sdJwtHasher: SdJwtHasher) : Result<SdjwtDisclosure > {
    val sd = mutableListOf<Value>()
    val disclosures = mutableListOf<String>()
    //filter disclosures for illegal ones
    val objectDisclosures = objectDisclosures.filter { oc -> !UNDISCLOSABLE_CLAIMS.any { forbidden ->
        forbidden.isSubPath(oc)
    } }
    // find all disclosures on our level
    val thisObject = objectDisclosures.filter { it.depth() == currentDepth}
    // find all disclosures only disclosable on a deeper level
    val otherObjects = objectDisclosures.filter { thisObject.all { other -> !other.isSubPath(it)} && it.depth() > currentDepth }

    val obj = claims.v1.toMutableMap()
    // we don't have anything on this level
//    if(thisObject.isEmpty() && deeperNestedObjects.isNotEmpty()) {
    val alreadyVisited = mutableListOf<ClaimsPointer>()
        for(otherO in otherObjects) {
            val ptr = otherO.toDepth(currentDepth)
            if(alreadyVisited.contains(ptr)) {
                continue
            }
            val claimName = ptr.key()
            alreadyVisited.add(ptr)

            val claimPointer = ClaimsPointer(listOf(claimName))
            if(claimName !is PointerPart.String) {
                continue
            }
            val element = claims[claimPointer]
            if(element.isEmpty()) {
                // it might be an optional claim, so skip it
                continue
            }
            val innerValue = element[0]
            val nested = otherObjects.filter { ptr.isSubPath(it) && it.depth() > currentDepth }
            when (innerValue) {
                is Value.Object -> {
                    val objs = createDisclosureForObject(innerValue, nested, currentDepth + 1, sdJwtHasher).getOrElse { return Result.failure(it) }
                    obj.put(claimName.v1, objs.disclosedObject)
                    disclosures.addAll(objs.disclosure)
                }
                is Value.Array -> {
                    val objs = createDisclosureForArray(innerValue, nested, currentDepth + 1, sdJwtHasher).getOrElse { return Result.failure(it) }
                    obj.put(claimName.v1, objs.disclosedObject)
                    disclosures.addAll(objs.disclosure)
                }
                else -> {continue}
            }
        }
//    }
    for (to in thisObject) {
        val nestedDislcosure = objectDisclosures.filter { to.isSubPath(it) && to != it }
        // we have nested disclosures, so do that first
        val results = claims[to.fromDepth(currentDepth)]
        // it must be single entry
        if(results.size != 1) {
            return Result.failure(IssuanceError.DisclosurePathNotResolved(to))
        }
        val element = results[0]
        // get this property's name
        val key = to.key()
        // it needs to be a string (otherwise we should be in array or somewhere else)
        if(key !is PointerPart.String) {
            return Result.failure(IssuanceError.KeyShouldBeString(to))
        }
        var replace = false
        val d = if(nestedDislcosure.isNotEmpty()) {
            val obj = when (element) {
                is Value.Object -> createDisclosureForObject(element, nestedDislcosure, currentDepth + 1, sdJwtHasher)
                is Value.Array -> {
                    // if we need a disclosure for the array parts, dont remove
                    replace = true
                    createDisclosureForArray(element, nestedDislcosure, currentDepth + 1, sdJwtHasher)
                }
                else -> {
                    Result.failure<SdjwtDisclosure>(IssuanceError.ElementNotDisclosable(element, nestedDislcosure))
                }
            }.getOrElse { return Result.failure(it) }
            disclosures.addAll(obj.disclosure)
            obj.disclosedObject
        } else {
           element
        }
        // value is disclosable
        // generate random nonce for salting
        val nonceStr = sdJwtHasher.generatedBlinding(generateNonce(32UL))
        val nonce = Value.String(nonceStr)
        // encode to string and base64

        val disclosure = base64UrlEncode(Json.encodeToString(Value.Array(listOf(nonce, Value.String(key.v1), d))).encodeToByteArray())

        // calculate the hash from the base64encoded string
        val hash = sdJwtHasher.hash(disclosure, nonceStr, key.v1, d)
        // add it to this obejcts sd array
        sd.add(Value.String(hash))
        disclosures.add(disclosure)
        if(replace) {
            obj.put(key.v1, d)
        } else {
            obj.remove(key.v1)
        }
    }
    if(sd.isNotEmpty()) {
        obj["_sd"] = Value.Array(sd)
    }
    if(sdJwtHasher.sdAlgParams() != Value.Null && currentDepth == 1) {
        obj["_sd_alg_param"] = sdJwtHasher.sdAlgParams()
    }
    if(currentDepth == 1) {
        obj["_sd_alg"] = sdJwtHasher.sdAlg()
    }
    return Result.success(SdjwtDisclosure(Value.Object(obj), disclosures))
}
fun createDisclosureForArray(array: Value.Array, objectDisclosures: List<ClaimsPointer>, currentDepth: Int, sdJwtHasher: SdJwtHasher) : Result<SdjwtDisclosure> {
    // find all disclosures on our level
    val thisObject = objectDisclosures.filter { it.depth() == currentDepth}
    val restObject = objectDisclosures.filter { it.depth() > currentDepth}
    // for array disclosure we only support NULL (slicing == all arguments)
    if (thisObject.size != 1) {
        return Result.failure(IssuanceError.ArrayMustRevealAll(thisObject))
    }
    val thisPtr = thisObject[0].key()
    if(thisPtr !is PointerPart.Null) {
        return Result.failure(IssuanceError.ArrayMustRevealAll(thisObject))
    }
    var disclosures = mutableListOf<String>()
    var obj = mutableListOf<Value>()
    for(element in array.v1) {
        val dis = when(element) {
            is Value.Object -> createDisclosureForObject(element, restObject, currentDepth + 1, sdJwtHasher)
            is Value.Array -> createDisclosureForArray(element, restObject, currentDepth + 1, sdJwtHasher)
            else -> {
                Result.success(SdjwtDisclosure(element, listOf()))
            }
        }.getOrElse { return Result.failure(it) }
        disclosures.addAll(dis.disclosure)
        val nonceStr =  sdJwtHasher.generatedBlinding(generateNonce(32UL))
        val nonce = Value.String(nonceStr)
        Value.Array(listOf(nonce, element))
        // encode to string and base64
        val disclosure = base64UrlEncode(Json.encodeToString(Value.Array(listOf(nonce, dis.disclosedObject))).encodeToByteArray())
        // calculate the hash from the base64encoded string
        val hash = sdJwtHasher.hash(disclosure, nonceStr, null, dis.disclosedObject)
        disclosures.add(disclosure)
        obj.add(Value.Object(mapOf("..." to Value.String(hash))))
    }
    return Result.success(SdjwtDisclosure(Value.Array(obj), disclosures))
}

class SdJwt(val innerJwt: SdJwtRust) : ClaimGetter {
    companion object {
        val SD_JWT_FORMATS : Array<String> = arrayOf("dc+sd-jwt", "vc+sd-jwt")
        fun parse(str: String): SdJwt {
            return SdJwt(decodeSdjwt(str))
        }
        fun create(claims: Value, disclosures: List<ClaimsPointer>, keyId: String, key: SignatureCreator, pubKeyJwk: Value?, hashAlg: String = "sha-256") : SdJwt? {
            val sdjwtHasher = SdJwtHasher.fromStr(hashAlg)
            val header = Header(alg = key.alg(), kid = keyId)
            if (!claims.isObject()) {
                return null
            }
            val keyClaims = claims.asObject()!!.toMutableMap()
            if(pubKeyJwk != null) {
                val cnf = mutableMapOf("jwk" to pubKeyJwk)
                keyClaims.put("cnf", Value.Object(cnf))
            }
            val claimObject = Value.Object(keyClaims)
            // we start at level 1
            val sdjwt = createDisclosureForObject(claimObject, disclosures, 1, sdjwtHasher)
            if(sdjwt.isFailure) {
                return null
            }
            val headerEncoded = base64UrlEncode(Json.encodeToString(Header.serializer(),header).encodeToByteArray())
            val sdjwtDisclosure = sdjwt.getOrThrow()
            val bodyEncoded = base64UrlEncode(Json.encodeToString(sdjwtDisclosure.disclosedObject).encodeToByteArray())
            val msgPayload = "$headerEncoded.$bodyEncoded"
            val signature = base64UrlEncode(key.sign(msgPayload.encodeToByteArray()))
            val jwt = "$msgPayload.$signature"
            val disclosureString = sdjwtDisclosure.disclosure.joinToString("~")
            return parse("$jwt~$disclosureString~")
        }
    }

    // We need to optimize this currently we have way too many calls to select
    fun resolvePointer(ptr: List<PointerPart>) : List<List<PointerPart>> {
        val p = ClaimsPointer(ptr)
        return p.resolvePtr(this.innerJwt.claims)
    }

    fun presentation(): SdJwtBuilder {
        return SdJwtBuilder.fromSdjwt(this.innerJwt)
    }

    override fun get(pointer: Selector): List<Value> {
        return this.innerJwt.claims[pointer]
    }

    fun getMetadata(): SdJwtVcMetadata {
        val claims = innerJwt.claims
        return SdJwtVcMetadata(
            issuer = claims["iss"].asString(),
            vct = requireNotNull(claims["vct"].asString()),
            issuedAt = claims["iat"].let { it.asLong() ?: it.asString()?.toLongOrNull() },
            expiresAt = claims["exp"].let { it.asLong() ?: it.asString()?.toLongOrNull() },
            notBefore = claims["nbf"].let { it.asLong() ?: it.asString()?.toLongOrNull() },
            confirmation = claims["cnf"].asString(),
            status = claims["status"].asString(),
            subject = claims["sub"].asString()
        )
    }

    fun getOriginalNumClaims(): Int {
        fun helper(root: Value): Int {
            var result = 0

            if (root is Value.Object) {
                for ((key, value) in root.v1) {
                    if (key == "_sd" && value is Value.Array) {
                        result += value.v1.size
                    }
                    if (key != "_sd" && value is Value.Object) {
                        result += helper(value)
                    }
                }
            }

            return result
        }
        return helper(innerJwt.claims)
    }

    fun getNumDisclosed(): Int {
        return innerJwt.disclosuresMap.size
    }

    fun isSignatureValid(): Boolean {
        return SdJwtVcSignatureResolver.isSignatureValid(innerJwt.originalJwt)
    }
}

fun SdJwtRust.toKt() : SdJwt {
    return SdJwt(this)
}
fun SdJwt.toJson() : String? {
    return this.innerJwt.toJson()
}

fun SdJwtRust.toJson() : String? {
    return encodeToJson(this)
}

operator fun SdJwt.get(s: Selector) : List<Value> {
    return this.get(s)
}
