/* Copyright 2024 Ubique Innovation AG

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
package ch.ubique.heidi.sample.wallet.compose.components

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Box
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalInspectionMode
import ch.ubique.heidi.sample.wallet.utils.QrCodeGenerator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

@Composable
fun QrCodeImage(
	content: String,
	modifier: Modifier = Modifier,
) {
	val bitmapState = rememberQrCodeBitmap(content)

	AnimatedContent(
		targetState = bitmapState.value,
		transitionSpec = {
			fadeIn(animationSpec = tween(220, delayMillis = 90)) togetherWith fadeOut(animationSpec = tween(90))
		}
	) { bitmap ->
		if (bitmap != null) {
			Image(
				bitmap = bitmap,
				contentDescription = null,
				modifier = modifier
			)
		} else {
			Box(
				modifier = modifier,
				contentAlignment = Alignment.Center,
			) {
				CircularProgressIndicator()
			}
		}
	}
}

@Composable
private fun rememberQrCodeBitmap(content: String): State<ImageBitmap?> {
	return if (LocalInspectionMode.current) {
		// Render synchronously for the inspection preview
		val bitmap = QrCodeGenerator.createQRCode(content)
		remember { mutableStateOf(bitmap?.asImageBitmap()) }
	} else {
		// Render asynchronously in normal mode
		val initial: ImageBitmap? = null
		produceState(initialValue = initial) {
			// Produce the bitmap state on the IO dispatcher because rendering can take quite a few milliseconds
			withContext(Dispatchers.IO) {
				val bitmap = QrCodeGenerator.createQRCode(content)
				value = bitmap?.asImageBitmap()
			}
		}
	}
}
