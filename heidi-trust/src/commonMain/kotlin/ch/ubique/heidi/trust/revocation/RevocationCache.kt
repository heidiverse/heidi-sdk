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

package ch.ubique.heidi.trust.revocation

import ch.ubique.heidi.trust.di.HeidiTrustKoinComponent
import org.koin.core.module.dsl.singleOf
import org.koin.dsl.module
import kotlin.time.Clock
import kotlin.time.ExperimentalTime

@OptIn(ExperimentalTime::class)
class RevocationCache : HeidiTrustKoinComponent {
    private val cacheDuration: Long = 5 * 1000 * 60
    companion object {
        val koinModule = module {
            singleOf(::RevocationCache)
        }
    }
    data class CachedEntry<T>(val isRevoked : T, val insertedAt: Long)
    private val entryCache = mutableMapOf<String, CachedEntry<Boolean>>()
    private val listCache = mutableMapOf<String, CachedEntry<String>>()
    fun insertResult(url: String, index: Int, isRevoked: Boolean) {
        entryCache["$url $index"] = CachedEntry(isRevoked, Clock.System.now().toEpochMilliseconds())
    }
    fun getResult(url: String, index: Int) : Boolean? {
        return entryCache["$url $index"]?.let {
            if(it.insertedAt +  cacheDuration < Clock.System.now().toEpochMilliseconds()) {
                return null
            }
            it.isRevoked
        }
    }
    fun insertList(url: String, list: String) {
        listCache[url] = CachedEntry(list, Clock.System.now().toEpochMilliseconds())
    }
    fun getList(url: String) : String? {
        return listCache[url]?.let {
            if(it.insertedAt +  cacheDuration < Clock.System.now().toEpochMilliseconds()) {
                return null
            }
            it.isRevoked
        }
    }
}
