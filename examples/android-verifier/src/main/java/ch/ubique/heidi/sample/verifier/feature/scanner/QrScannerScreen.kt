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
package ch.ubique.heidi.sample.verifier.feature.scanner

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.RoundRect
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.clipPath
import androidx.compose.ui.graphics.drawscope.drawIntoCanvas
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import ch.ubique.heidi.sample.verifier.extensions.dpToPx
import ch.ubique.qrscanner.compose.QrScanner
import ch.ubique.qrscanner.scanner.BarcodeFormat
import ch.ubique.qrscanner.scanner.ScanningMode
import ch.ubique.qrscanner.state.DecodingState
import ch.ubique.qrscanner.zxing.decoder.GlobalHistogramImageDecoder
import ch.ubique.qrscanner.zxing.decoder.HybridImageDecoder

@Composable
fun QrScannerScreen(
	qrCodeScannerViewModel: QrScannerViewModel,
	callbacks: QrScannerScreenCallbacks,
) {
	var qrCode: String? by remember { mutableStateOf(null) }
	LaunchedEffect(qrCode) {
		qrCode?.let { callbacks.onSuccess(it) }
	}

	QrScannerScreenContent(
		viewModel = qrCodeScannerViewModel,
		scannerCallback = {
			val result = qrCodeScannerViewModel.evaluateScannerResult(it)
			if (result is DecodingResult.Valid) {
				qrCode = result.content
			}
		},
		onPermissionInSettingsChange = callbacks::onPermissionInSettingsChange,
	)
}

@Composable
fun QrScannerScreenContent(
	viewModel: QrScannerViewModel,
	scannerCallback: (DecodingState) -> Unit,
	onPermissionInSettingsChange: () -> Unit,
) {
	LaunchedEffect(viewModel) {
		viewModel.startScanning()
	}

	QrScannerContent(
		errorResource = viewModel.error.collectAsStateWithLifecycle(initialValue = null).value,
		isLightOn = viewModel.isLightOn.collectAsStateWithLifecycle(),
		scannerCallback = scannerCallback,
		onFlashlightButtonClicked = viewModel::switchLightState,
	)

	CameraPermissionHandler(onPermissionInSettingsChange)
}

@Composable
private fun QrScannerContent(
	errorResource: Int?,
	isLightOn: State<Boolean>,
	scannerCallback: (DecodingState) -> Unit,
	onFlashlightButtonClicked: () -> Unit,
) {
	Box(
		Modifier
			.fillMaxSize()
			.background(Color.White)
	) {
		QrScanner(
			imageDecoders = listOf(
				GlobalHistogramImageDecoder(listOf(BarcodeFormat.QR_CODE)),
				HybridImageDecoder(listOf(BarcodeFormat.QR_CODE)),
			),
			scannerCallback = scannerCallback,
			modifier = Modifier.fillMaxSize(),
			scanningMode = ScanningMode.PARALLEL,
			isFlashEnabled = isLightOn
		)

		QrScannerOverlay(
			errorResource = errorResource,
			isLightOn = isLightOn.value,
			onFlashlightButtonClicked = onFlashlightButtonClicked
		)
	}
}

@Composable
private fun QrScannerOverlay(
	errorResource: Int?,
	isLightOn: Boolean,
	onFlashlightButtonClicked: () -> Unit,
) {
	val regularFontSize = 16.sp
	val error = errorResource?.let { stringResource(id = it) }
	Box(Modifier.fillMaxSize(), contentAlignment = Alignment.BottomCenter) {
		val spacing = 60.dpToPx
		val errorSpacing = 30.dpToPx
		val strokeWidth = 3.dpToPx
		Canvas(modifier = Modifier.fillMaxSize(), onDraw = {
			val qrWindowSize = size.width - 2 * spacing
			val bottomOffset = spacing
			val innerShape = Path().apply {
				addRoundRect(
					RoundRect(
						spacing,
						center.y - qrWindowSize / 2 - bottomOffset,
						size.width - spacing,
						center.y + qrWindowSize / 2 - bottomOffset,
						CornerRadius(20f, 20f)
					)
				)
			}
			drawPath(
				innerShape,
				if (error == null) Color.White else Color.Red,
				style = Stroke(width = strokeWidth)
			)
			clipPath(innerShape, clipOp = ClipOp.Difference) {
				drawRect(SolidColor(Color.Black.copy(alpha = 0.8f)))
			}
			if (error != null) {
				drawIntoCanvas {
					it.nativeCanvas.drawText(
						error,
						center.x,
						center.y - qrWindowSize / 2 - bottomOffset - errorSpacing,
						android.graphics.Paint().apply {
							textAlign = android.graphics.Paint.Align.CENTER
							textSize = regularFontSize.toPx()
							color = Color.Red.toArgb()
						}
					)
				}
			}
		})

//		Row(
//			modifier = Modifier.padding(all = 48.dp)
//		) {
//			Spacer(modifier = Modifier.weight(1f))
//			FloatingRoundActionButton(
//				iconId = if (isLightOn) R.drawable.ic_light else R.drawable.ic_light,
//				color = if (isLightOn) Color.White else Color.Black,
//				iconTint = if (isLightOn) Color.Black else Color.White,
//				onClick = onFlashlightButtonClicked
//			)
//		}
	}
}

