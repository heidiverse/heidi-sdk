package org.kapunsdk.util.random

import kotlin.random.Random

class RandomGenerator(private val source: Random = Random.Default) {

	companion object {
		private const val ALPHANUMERIC_CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	}

	fun generateAlphanumericString(length: Int): String {
		return (1..length).map { ALPHANUMERIC_CHARACTERS.random(source) }.joinToString("")
	}

	fun generateByteArray(size: Int): ByteArray {
		return source.nextBytes(size)
	}

}