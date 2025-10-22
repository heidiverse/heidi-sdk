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
package ch.ubique.heidi.sample.wallet.feature.proximity

import androidx.compose.animation.AnimatedContent
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.State
import androidx.compose.ui.Modifier
import ch.ubique.heidi.proximity.wallet.ProximityWalletState
import ch.ubique.heidi.sample.wallet.compose.components.QrCodeImage
import ch.ubique.heidi.sample.wallet.feature.scanner.QrScannerScreen
import ch.ubique.heidi.sample.wallet.feature.scanner.QrScannerScreenCallbacks
import ch.ubique.heidi.sample.wallet.feature.scanner.QrScannerViewModel

@Composable
fun ProximityScreen(
	proximityState: State<ProximityWalletState>,
	qrScannerViewModel: QrScannerViewModel,
	scannerCallbacks: QrScannerScreenCallbacks,
	onSubmitDocumentClicked: () -> Unit,
	onStartEngagementClicked: () -> Unit,
	onResetState: () -> Unit
) {
	Scaffold { innerPadding ->
		AnimatedContent(
			modifier = Modifier.padding(innerPadding),
			targetState = proximityState.value,
			contentKey = { it.javaClass.simpleName },
		) { state ->

			Box(Modifier.fillMaxSize()) {
				when (state) {
					is ProximityWalletState.Initial -> {
//						QrScannerScreen(
//							qrScannerViewModel,
//							scannerCallbacks,
//						)
						Button(onClick = {
							onStartEngagementClicked()
						}) {
							Text("Start")
						}
					}
					is ProximityWalletState.ReadyForEngagement -> {
						QrCodeImage(
							state.qrCodeData, modifier = Modifier
								.fillMaxWidth()
								.aspectRatio(1f)
						)
					}
					is ProximityWalletState.Connecting -> {
						Text("Connecting to ${state.verifierName}")
					}
					is ProximityWalletState.Connected -> {
						Text("Connected to ${state.verifierName}")
					}
					is ProximityWalletState.RequestingDocuments -> {
						Column(Modifier.verticalScroll(rememberScrollState())) {
							Text("Verifier requests documents: ${state.request}", maxLines = 20)
							Button(onClick = onSubmitDocumentClicked) {
								Text("Submit document")
							}
						}
					}
					is ProximityWalletState.SubmittingDocuments -> {
						Text("Submitting documents to verifier")
					}
					is ProximityWalletState.PresentationCompleted -> {
						Text("Verification completed")
						Button(onClick = {
							onResetState()
						}){
							Text("Reset")
						}
					}
					is ProximityWalletState.Disconnected -> {
						Text("Disconnected")
						Button(onClick = {
							onStartEngagementClicked()
						}) {
							Text("Start")
						}
					}
					is ProximityWalletState.Error -> {
						Text(state.throwable.stackTraceToString())
					}
				}
			}
		}
	}
}
