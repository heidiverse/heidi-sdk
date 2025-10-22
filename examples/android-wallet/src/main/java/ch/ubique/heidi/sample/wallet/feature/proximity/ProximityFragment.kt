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

import android.Manifest
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.collectAsState
import androidx.fragment.app.Fragment
import ch.ubique.heidi.sample.wallet.compose.theme.HeidiTheme
import ch.ubique.heidi.sample.wallet.databinding.FragmentComposeBinding
import ch.ubique.heidi.sample.wallet.feature.scanner.QrScannerScreenCallbacks
import ch.ubique.heidi.sample.wallet.feature.scanner.QrScannerViewModel
import org.koin.androidx.viewmodel.ext.android.viewModel
import org.koin.core.component.KoinComponent

class ProximityFragment : Fragment(), KoinComponent {

	companion object {
		val TAG = "ProximityFragment"

		fun newInstance() = ProximityFragment()
	}

	private val viewModel by viewModel<ProximityViewModel>()
	private val qrScannerViewModel by viewModel<QrScannerViewModel>()

	private var _binding: FragmentComposeBinding? = null
	private val binding get() = _binding!!

	private val bluetoothPermissionLauncher = registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { permissions ->
		if (permissions.all { it.value }) {
			locationPermissionLauncher.launch(Manifest.permission.ACCESS_FINE_LOCATION)
		}
	}

	private val locationPermissionLauncher = registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
		if (granted) {
			// TODO Handle permissions properly?
		}
	}

	override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
		_binding = FragmentComposeBinding.inflate(inflater, container, false)
		return binding.root
	}

	override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
		super.onViewCreated(view, savedInstanceState)

		bluetoothPermissionLauncher.launch(
			arrayOf(
				Manifest.permission.BLUETOOTH,
				Manifest.permission.BLUETOOTH_SCAN,
				Manifest.permission.BLUETOOTH_ADVERTISE,
				Manifest.permission.BLUETOOTH_CONNECT,
			)
		)

		binding.composeView.setContent {
			HeidiTheme {
				ProximityScreen(
					proximityState = viewModel.proximityState.collectAsState(),
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
					onSubmitDocumentClicked = viewModel::submitDocument,
					onStartEngagementClicked = viewModel::startEngagementMdl,
					onResetState = viewModel::reset
				)
			}
		}
	}

	override fun onDestroyView() {
		super.onDestroyView()
		_binding = null
	}

}
