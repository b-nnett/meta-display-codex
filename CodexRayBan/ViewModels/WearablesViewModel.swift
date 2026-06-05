/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
 */

//
// WearablesViewModel.swift
//
// View model managing DAT SDK registration, device state, and per-device link
// state listeners. Each connected device gets a DeviceItemState that tracks
// its link state in real time via addLinkStateListener.
//

import MWDATCore
import Observation
import SwiftUI

// MARK: - DeviceItemState

@Observable
@MainActor
class DeviceItemState: Identifiable {
  let identifier: DeviceIdentifier
  var linkState: LinkState
  var compatibility: Compatibility
  var deviceName: String
  var deviceTypeValue: String

  @ObservationIgnored private var linkStateToken: AnyListenerToken?

  nonisolated var id: DeviceIdentifier { identifier }

  init(device: Device) {
    self.identifier = device.identifier
    self.deviceName = device.nameOrId()
    self.deviceTypeValue = device.deviceType().rawValue
    self.linkState = device.linkState
    self.compatibility = device.compatibility()

    linkStateToken = device.addLinkStateListener { [weak self] _ in
      Task { @MainActor [weak self] in
        guard let self else { return }
        self.linkState = device.linkState
        self.compatibility = device.compatibility()
        self.deviceName = device.nameOrId()
      }
    }
  }
}

// MARK: - WearablesViewModel

@Observable
@MainActor
class WearablesViewModel {
  var deviceItemStates: [DeviceItemState] = []
  var registrationState: RegistrationState
  var showError: Bool = false
  var errorMessage: String = ""
  var requiresFirmwareUpdate: Bool = false

  @ObservationIgnored private var registrationTask: Task<Void, Never>?
  @ObservationIgnored private var deviceStreamTask: Task<Void, Never>?
  private var deviceCompatibility: [DeviceIdentifier: Compatibility] = [:]
  private var compatibilityListenerTokens: [DeviceIdentifier: AnyListenerToken] = [:]
  let wearables: WearablesInterface

  init(wearables: WearablesInterface) {
    self.wearables = wearables
    self.registrationState = wearables.registrationState

    deviceStreamTask = Task { [weak self] in
      guard let wearables = self?.wearables else { return }
      for await deviceIds in wearables.devicesStream() {
        guard let self else { return }
        self.deviceItemStates = deviceIds.compactMap { deviceId in
          guard let device = wearables.deviceForIdentifier(deviceId) else { return nil }
          return DeviceItemState(device: device)
        }
        self.monitorDeviceCompatibility(deviceIds: deviceIds)
      }
    }

    registrationTask = Task { [weak self] in
      guard let wearables = self?.wearables else { return }
      for await state in wearables.registrationStateStream() {
        guard let self else { return }
        self.registrationState = state
      }
    }
  }

  isolated deinit {
    registrationTask?.cancel()
    deviceStreamTask?.cancel()
    for token in compatibilityListenerTokens.values {
      Task { await token.cancel() }
    }
  }

  func connectGlasses() async {
    guard registrationState != .registering else { return }
    do {
      try await wearables.startRegistration()
    } catch {
      showError(error.description)
    }
  }

  func disconnectGlasses() async {
    do {
      try await wearables.startUnregistration()
    } catch {
      showError(error.description)
    }
  }

  func openFirmwareUpdate() {
    Task {
      do {
        try await wearables.openFirmwareUpdate()
      } catch {
        showError(error.localizedDescription)
      }
    }
  }

  func openDATGlassesAppUpdate() {
    Task {
      do {
        try await wearables.openDATGlassesAppUpdate()
      } catch {
        showError(error.localizedDescription)
      }
    }
  }

  func showError(_ error: String) {
    let normalized = error.lowercased()
    guard !normalized.contains("under development") && !normalized.contains("development features") else {
      if CodexRuntimeEnvironment.isVerboseLoggingEnabled {
        NSLog("[Codex wearables] suppressed SDK development-feature alert: %@", error)
      }
      return
    }
    errorMessage = error
    showError = true
  }

  func dismissError() {
    showError = false
  }

  /// Keeps firmware update state in sync with the current device list.
  /// Compatibility listeners are tied to `Device` instances, so they must be
  /// canceled when an identifier leaves the stream and recreated if it returns.
  private func monitorDeviceCompatibility(deviceIds: [DeviceIdentifier]) {
    let deviceSet = Set(deviceIds)
    let removedDeviceIds = compatibilityListenerTokens.keys.filter { !deviceSet.contains($0) }

    // The devices stream only emits identifiers. Cancel removed listener tokens
    // explicitly so a forgotten and rediscovered device gets a fresh listener.
    for deviceId in removedDeviceIds {
      if let token = compatibilityListenerTokens.removeValue(forKey: deviceId) {
        Task { await token.cancel() }
      }
      deviceCompatibility[deviceId] = nil
    }
    updateRequiresFirmwareUpdate()

    // Add listeners only for new identifiers; existing tokens keep reporting
    // compatibility changes until the identifier leaves the device stream.
    for deviceId in deviceIds {
      guard compatibilityListenerTokens[deviceId] == nil else { continue }
      guard let device = wearables.deviceForIdentifier(deviceId) else { continue }
      deviceCompatibility[deviceId] = device.compatibility()
      updateRequiresFirmwareUpdate()

      let token = device.addCompatibilityListener { [weak self] compatibility in
        Task { [weak self] in
          await self?.handleCompatibilityChange(compatibility, deviceId: deviceId)
        }
      }
      compatibilityListenerTokens[deviceId] = token
    }
  }

  private func updateRequiresFirmwareUpdate() {
    requiresFirmwareUpdate = deviceCompatibility.values.contains(.deviceUpdateRequired)
  }

  private func handleCompatibilityChange(
    _ compatibility: Compatibility,
    deviceId: DeviceIdentifier
  ) {
    deviceCompatibility[deviceId] = compatibility
    deviceItemStates.first { $0.identifier == deviceId }?.compatibility = compatibility
    updateRequiresFirmwareUpdate()
  }
}
