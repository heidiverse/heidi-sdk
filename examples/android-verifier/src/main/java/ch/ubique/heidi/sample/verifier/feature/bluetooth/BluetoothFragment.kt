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
package ch.ubique.heidi.sample.verifier.feature.bluetooth

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.compose.runtime.collectAsState
import androidx.fragment.app.Fragment
import ch.ubique.heidi.sample.verifier.compose.theme.HeidiTheme
import ch.ubique.heidi.sample.verifier.databinding.FragmentComposeBinding
import ch.ubique.heidi.sample.verifier.feature.scanner.QrScannerScreenCallbacks
import ch.ubique.heidi.sample.verifier.feature.scanner.QrScannerViewModel
import org.koin.androidx.viewmodel.ext.android.viewModel

class BluetoothFragment : Fragment() {

	companion object {
		val TAG = "BluetoothFragment"

		fun newInstance() = BluetoothFragment()
	}

	private val viewModel by viewModel<BluetoothViewModel>()

	private val qrScannerViewModel by viewModel<QrScannerViewModel>()

	private var _binding: FragmentComposeBinding? = null
	private val binding get() = _binding!!

	override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
		_binding = FragmentComposeBinding.inflate(inflater, container, false)
		return binding.root
	}

	override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
		super.onViewCreated(view, savedInstanceState)
		binding.composeView.setContent {
			HeidiTheme {
				BluetoothScreen(
					state = viewModel.bluetoothState.collectAsState(),
					log = viewModel.bluetoothLog.collectAsState(),
					onStartServer = viewModel::startServerMode,
					onStartClient = viewModel::startClientMode,
					qrScannerViewModel = qrScannerViewModel,
					scannerCallbacks = object : QrScannerScreenCallbacks {
						override fun onPermissionInSettingsChange() {
							val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
								.addCategory(Intent.CATEGORY_DEFAULT)
								.setData(Uri.parse("package:${requireContext().packageName}"))
							startActivity(intent)
						}

						override fun onSuccess(data: String) {
							viewModel.startEngagement(data)
						}
					},
					sendMessage = viewModel::sendMessage,
					onStopClicked = viewModel::stop,
				)
			}
		}
	}

	override fun onDestroyView() {
		super.onDestroyView()
		_binding = null
	}

}
