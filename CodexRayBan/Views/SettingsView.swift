/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
 */

//
// SettingsView.swift
//
// Registration and device connection screen. Shows glasses registration state
// and lists connected devices with real-time link state updates.
//

import MWDATCore
import SwiftUI
import UIKit

struct SettingsViewModel {
  let registrationState: RegistrationState
  let deviceItemStates: [DeviceItemState]
  let requiresFirmwareUpdate: Bool
  let requiresDATAppUpdate: Bool
  private let connectGlassesAction: () -> Void
  private let disconnectGlassesAction: () -> Void
  private let openFirmwareUpdateAction: () -> Void
  private let openDATGlassesAppUpdateAction: () -> Void

  init(
    registrationState: RegistrationState,
    deviceItemStates: [DeviceItemState],
    requiresFirmwareUpdate: Bool,
    requiresDATAppUpdate: Bool,
    connectGlasses: @escaping () -> Void,
    disconnectGlasses: @escaping () -> Void,
    openFirmwareUpdate: @escaping () -> Void,
    openDATGlassesAppUpdate: @escaping () -> Void
  ) {
    self.registrationState = registrationState
    self.deviceItemStates = deviceItemStates
    self.requiresFirmwareUpdate = requiresFirmwareUpdate
    self.requiresDATAppUpdate = requiresDATAppUpdate
    self.connectGlassesAction = connectGlasses
    self.disconnectGlassesAction = disconnectGlasses
    self.openFirmwareUpdateAction = openFirmwareUpdate
    self.openDATGlassesAppUpdateAction = openDATGlassesAppUpdate
  }

  var hasCompatibilityIssue: Bool {
    requiresFirmwareUpdate || requiresDATAppUpdate
  }

  func connectGlasses() {
    connectGlassesAction()
  }

  func disconnectGlasses() {
    disconnectGlassesAction()
  }

  func openFirmwareUpdate() {
    openFirmwareUpdateAction()
  }

  func openDATGlassesAppUpdate() {
    openDATGlassesAppUpdateAction()
  }
}

struct SettingsView: View {
  let viewModel: SettingsViewModel
  var authViewModel: CodexAuthViewModel
  var displayViewModel: DisplayViewModel
  var transcriptionViewModel: CodexTranscriptionViewModel
  var displayAppBridge: CodexDisplayAppBridge
  var workspaceViewModel: CodexWorkspaceViewModel
  var displayHostID: String?
  var displayHostName: String

  @State private var transcriptionKeyDraft = ""
  @State private var transcriptionAlertMessage: String?

  var body: some View {
    @Bindable var authViewModel = authViewModel

    List {
      systemSection
      devicesSection
      codexSection
      voiceSection
      displaySection
      if CodexRuntimeEnvironment.isDeveloperDiagnosticsEnabled {
        diagnosticsSection
        authLogSection
      }
    }
    .navigationTitle("Settings")
    .navigationBarTitleDisplayMode(.inline)
    .sheet(item: $authViewModel.activeOAuthRequest) { request in
      CodexOAuthSessionPresenter(
        request: request,
        onCallback: { url, request in
          Task {
            await authViewModel.handleOAuthCallback(url, request: request)
          }
        },
        onCancel: { request in
          if authViewModel.activeOAuthRequest?.id == request.id {
            authViewModel.activeOAuthRequest = nil
          }
        },
        onError: { message in
          authViewModel.activeOAuthRequest = nil
          authViewModel.errorMessage = message
        }
      )
    }
    .sheet(isPresented: $authViewModel.showsTokenImport) {
      if CodexRuntimeEnvironment.isDeveloperDiagnosticsEnabled {
        TokenImportView { token in
          authViewModel.importAccessToken(token)
        }
      }
    }
    .task {
      await transcriptionViewModel.refreshPermissionStatus()
    }
    .alert("Voice input", isPresented: transcriptionAlertIsPresented) {
      Button("OK") {
        transcriptionAlertMessage = nil
      }
    } message: {
      Text(transcriptionAlertMessage ?? transcriptionViewModel.errorMessage ?? "Voice input is unavailable.")
    }
  }

  // MARK: - System

  private var systemSection: some View {
    Section("System") {
      HStack {
        registrationIcon
        Text(registrationLabel)
          .foregroundStyle(registrationColor)
        Spacer()
        registrationAction
      }

      if viewModel.hasCompatibilityIssue {
        CompatibilityIssueCard(
          showFirmwareUpdate: viewModel.requiresFirmwareUpdate,
          showDATAppUpdate: viewModel.requiresDATAppUpdate,
          onOpenFirmwareUpdate: viewModel.openFirmwareUpdate,
          onOpenDATAppUpdate: viewModel.openDATGlassesAppUpdate
        )
      }
    }
  }

  private var registrationIcon: some View {
    Group {
      switch viewModel.registrationState {
      case .unavailable:
        Image(systemName: "xmark.circle.fill")
          .foregroundStyle(.red)
      case .available:
        Image(systemName: "xmark.circle.fill")
          .foregroundStyle(.yellow)
      case .registering:
        Image(systemName: "ellipsis.circle.fill")
          .foregroundStyle(.orange)
      case .registered:
        Image(systemName: "checkmark.circle.fill")
          .foregroundStyle(.green)
      @unknown default:
        Image(systemName: "questionmark.circle.fill")
          .foregroundStyle(.gray)
      }
    }
  }

  private var registrationLabel: String {
    switch viewModel.registrationState {
    case .unavailable:
      "Unavailable"
    case .available:
      "Available"
    case .registering:
      "Registering..."
    case .registered:
      "Registered"
    @unknown default:
      "Unknown"
    }
  }

  private var registrationColor: Color {
    switch viewModel.registrationState {
    case .registered:
      .green
    case .registering:
      .orange
    case .unavailable:
      .red
    case .available:
      .yellow
    @unknown default:
      .gray
    }
  }

  @ViewBuilder
  private var registrationAction: some View {
    switch viewModel.registrationState {
    case .registered:
      SwiftUI.Button {
        viewModel.disconnectGlasses()
      } label: {
        Image(systemName: "trash")
          .foregroundStyle(.red)
      }
      .buttonStyle(.plain)
    case .unavailable, .available:
      SwiftUI.Button {
        viewModel.connectGlasses()
      } label: {
        Text("Register")
          .font(.subheadline.weight(.semibold))
          .foregroundStyle(.white)
          .padding(.horizontal, 20)
          .padding(.vertical, 8)
          .background(.blue, in: Capsule())
      }
      .buttonStyle(.plain)
    case .registering:
      ProgressView()
    @unknown default:
      EmptyView()
    }
  }

  // MARK: - Devices

  private var devicesSection: some View {
    Section("Devices") {
      if viewModel.deviceItemStates.isEmpty {
        Text("No devices found")
          .foregroundStyle(.secondary)
      } else {
        ForEach(viewModel.deviceItemStates) { state in
          DeviceRow(state: state)
        }
      }
    }
  }

  // MARK: - Codex

  private var codexSection: some View {
    Section("Codex") {
      settingsStatusRow(
        title: "OpenAI account",
        value: authViewModel.accountStatusText,
        systemImage: authViewModel.session.isSignedIn ? "checkmark.seal.fill" : "person.crop.circle.badge.xmark",
        color: authViewModel.session.isSignedIn ? .green : .secondary
      )

      settingsStatusRow(
        title: "Remote control",
        value: authViewModel.enrollmentStatusText,
        systemImage: authViewModel.session.remoteTokenIsFresh ? "key.fill" : "key",
        color: authViewModel.session.remoteTokenIsFresh ? .green : .secondary
      )

      settingsStatusRow(
        title: "Desktop hosts",
        value: authViewModel.hostStatusText,
        systemImage: "desktopcomputer",
        color: authViewModel.environments.contains(where: \.online) ? .green : .secondary
      )

      Button {
        runCodexConnectionAction()
      } label: {
        Label(codexConnectionButtonTitle, systemImage: codexConnectionButtonImage)
      }

      if CodexRuntimeEnvironment.isDeveloperDiagnosticsEnabled {
        Button {
          Task { await authViewModel.refreshHosts() }
        } label: {
          Label("Refresh hosts", systemImage: "desktopcomputer.and.arrow.down")
        }
        .disabled(!authViewModel.session.isSignedIn)

        Button {
          authViewModel.showsTokenImport = true
        } label: {
          Label("Import access token", systemImage: "square.and.arrow.down")
        }
      }

      Button(role: .destructive) {
        authViewModel.signOut()
      } label: {
        Label("Sign out", systemImage: "rectangle.portrait.and.arrow.right")
      }
      .disabled(!authViewModel.session.isSignedIn && !authViewModel.session.isRemoteEnrolled)
    }
  }

  private var voiceSection: some View {
    Section("Voice") {
      settingsStatusRow(
        title: "Transcription",
        value: transcriptionStatusText,
        systemImage: transcriptionStatusIcon,
        color: transcriptionStatusColor
      )

      settingsStatusRow(
        title: "Glasses microphone",
        value: transcriptionViewModel.datMicrophonePermission.displayName,
        systemImage: "eyeglasses",
        color: voicePermissionColor
      )

      settingsStatusRow(
        title: "Model",
        value: transcriptionViewModel.selectedModel,
        systemImage: "waveform",
        color: .secondary
      )

      Button {
        Task { await transcriptionViewModel.requestDATMicrophonePermission() }
      } label: {
        Label("Allow glasses microphone", systemImage: "mic.badge.plus")
      }
    }
  }

  private var transcriptionStatusText: String {
    if authViewModel.session.isSignedIn {
      return "Codex account"
    }
    if transcriptionViewModel.hasAPIKey {
      return "OpenAI key fallback"
    }
    return "Sign in needed"
  }

  private var transcriptionStatusIcon: String {
    authViewModel.session.isSignedIn || transcriptionViewModel.hasAPIKey ? "checkmark.seal.fill" : "mic.slash"
  }

  private var transcriptionStatusColor: Color {
    authViewModel.session.isSignedIn || transcriptionViewModel.hasAPIKey ? .green : .secondary
  }

  private var displaySection: some View {
    Section("Display") {
      settingsStatusRow(
        title: "Display session",
        value: displayViewModel.isConnected ? "Connected" : "Not connected",
        systemImage: displayViewModel.isConnected ? "checkmark.circle.fill" : "circle.dashed",
        color: displayViewModel.isConnected ? .green : .secondary
      )

      NavigationLink {
        CodexDisplayAppHostScreen(
          bridge: displayAppBridge,
          authViewModel: authViewModel,
          displayViewModel: displayViewModel,
          workspaceViewModel: workspaceViewModel,
          transcriptionViewModel: transcriptionViewModel,
          hostID: displayHostID,
          hostName: displayHostName
        )
      } label: {
        Label("Glasses display", systemImage: "eyeglasses")
      }

      Button {
        Task {
          await displayViewModel.sendCodexStatusCard(
            title: authViewModel.glassesStatusTitle,
            detail: authViewModel.glassesStatusDetail
          )
        }
      } label: {
        Label("Send Codex status", systemImage: "eyeglasses")
      }

      if CodexRuntimeEnvironment.isDeveloperDiagnosticsEnabled {
        Button {
          Task { await displayViewModel.sendHelloWorldCard() }
        } label: {
          Label("Send hello world", systemImage: "hand.wave.fill")
        }
      }

      Button(role: .destructive) {
        Task { await displayViewModel.detachFromDisplay() }
      } label: {
        Label("Disconnect display", systemImage: "xmark.circle")
      }
    }
  }

  private var diagnosticsSection: some View {
    Section("Auth Diagnostics") {
      ForEach(authViewModel.debugRows) { row in
        diagnosticRow(title: row.title, value: row.value)
      }

      if let errorMessage = authViewModel.errorMessage {
        Text(errorMessage)
          .foregroundStyle(.red)
        Button("Clear error") {
          authViewModel.clearError()
        }
      }
    }
  }

  private var authLogSection: some View {
    Section("Auth Log") {
      HStack {
        Button {
          UIPasteboard.general.string = authViewModel.authLogText
        } label: {
          Label("Copy log", systemImage: "doc.on.doc")
        }

        Spacer()

        Button(role: .destructive) {
          authViewModel.clearAuthLog()
        } label: {
          Label("Clear", systemImage: "trash")
        }
      }

      ForEach(authViewModel.authLogEntries) { entry in
        Text(entry.displayText)
          .font(.caption.monospaced())
          .textSelection(.enabled)
      }
    }
  }

  private var codexConnectionButtonTitle: String {
    if !authViewModel.session.isSignedIn {
      return "Sign in"
    }
    if !authViewModel.session.isRemoteEnrolled {
      return "Enroll"
    }
    return "Refresh remote token"
  }

  private var codexConnectionButtonImage: String {
    if !authViewModel.session.isSignedIn {
      return "person.badge.key.fill"
    }
    if !authViewModel.session.isRemoteEnrolled {
      return "link.badge.plus"
    }
    return "arrow.clockwise"
  }

  private var voicePermissionColor: Color {
    switch transcriptionViewModel.datMicrophonePermission {
    case .granted:
      .green
    case .denied:
      .red
    case .unknown, .unavailable:
      .secondary
    }
  }

  private var transcriptionAlertIsPresented: Binding<Bool> {
    Binding {
      transcriptionAlertMessage != nil || transcriptionViewModel.errorMessage != nil
    } set: { isPresented in
      if !isPresented {
        transcriptionAlertMessage = nil
        transcriptionViewModel.errorMessage = nil
      }
    }
  }

  private func runCodexConnectionAction() {
    if !authViewModel.session.isSignedIn {
      authViewModel.startNormalSignIn()
      return
    }

    if !authViewModel.session.isRemoteEnrolled {
      authViewModel.startRemoteEnrollment()
      return
    }

    Task { await authViewModel.refreshRemoteToken() }
  }

  private func saveTranscriptionKey() {
    do {
      try transcriptionViewModel.saveAPIKey(transcriptionKeyDraft)
      transcriptionKeyDraft = ""
    } catch {
      transcriptionAlertMessage = error.localizedDescription
    }
  }

  private func clearTranscriptionKey() {
    do {
      try transcriptionViewModel.clearAPIKey()
      transcriptionKeyDraft = ""
    } catch {
      transcriptionAlertMessage = error.localizedDescription
    }
  }

  private func settingsStatusRow(title: String, value: String, systemImage: String, color: Color) -> some View {
    HStack(spacing: 12) {
      Image(systemName: systemImage)
        .foregroundStyle(color)
        .frame(width: 24)
      VStack(alignment: .leading, spacing: 2) {
        Text(title)
        Text(value)
          .font(.caption)
          .foregroundStyle(.secondary)
      }
    }
  }

  private func diagnosticRow(title: String, value: String) -> some View {
    HStack {
      Text(title)
      Spacer()
      Text(value)
        .font(.caption.monospaced())
        .foregroundStyle(.secondary)
        .multilineTextAlignment(.trailing)
    }
  }
}

// MARK: - DeviceRow

private struct DeviceRow: View {
  var state: DeviceItemState

  var body: some View {
    HStack {
      VStack(alignment: .leading) {
        Text(state.deviceName)
          .font(.headline)
        Text(state.deviceTypeValue)
          .font(.subheadline)
          .foregroundStyle(.secondary)
        Text(state.identifier)
          .font(.caption)
          .foregroundStyle(.secondary)
      }
      Spacer()
      statusLabel
    }
  }

  private var statusLabel: some View {
    Text(statusText)
      .font(.subheadline)
      .fontWeight(.medium)
      .foregroundStyle(statusColor)
  }

  private var statusText: String {
    if state.compatibility == .deviceUpdateRequired {
      return "Update required"
    }

    switch state.linkState {
    case .disconnected:
      return "Disconnected"
    case .connecting:
      return "Connecting"
    case .connected:
      return "Connected"
    @unknown default:
      return "Unknown"
    }
  }

  private var statusColor: Color {
    if state.compatibility == .deviceUpdateRequired {
      return CompatibilityIssueCard.issueColor
    }

    switch state.linkState {
    case .disconnected:
      return .red
    case .connecting:
      return .yellow
    case .connected:
      return .green
    @unknown default:
      return .gray
    }
  }
}

// MARK: - CompatibilityIssueCard

private struct CompatibilityIssueCard: View {
  static let issueColor = Color(red: 0.54, green: 0.29, blue: 0.0)

  var showFirmwareUpdate: Bool
  var showDATAppUpdate: Bool
  var onOpenFirmwareUpdate: () -> Void
  var onOpenDATAppUpdate: () -> Void

  private static let issueBackground = Color(red: 1.0, green: 0.96, blue: 0.84)

  var body: some View {
    VStack(alignment: .leading, spacing: 14) {
      HStack(alignment: .top, spacing: 12) {
        Image(systemName: "exclamationmark.triangle.fill")
          .font(.title2)
          .foregroundStyle(Self.issueColor)

        VStack(alignment: .leading, spacing: 4) {
          Text(issueTitle)
            .font(.title3.weight(.semibold))
            .foregroundStyle(Self.issueColor)
          Text(issueMessage)
            .font(.subheadline)
            .foregroundStyle(Self.issueColor)
        }
      }

      VStack(spacing: 12) {
        if showFirmwareUpdate {
          compatibilityActionButton(updateFirmwareTitle, action: onOpenFirmwareUpdate)
        }

        if showDATAppUpdate {
          compatibilityActionButton(updateDATAppTitle, action: onOpenDATAppUpdate)
        }
      }
    }
    .frame(maxWidth: .infinity, alignment: .leading)
    .padding(20)
    .background(Self.issueBackground, in: RoundedRectangle(cornerRadius: 26))
  }

  private var issueTitle: String {
    "Compatibility issue"
  }

  private var issueMessage: String {
    switch (showFirmwareUpdate, showDATAppUpdate) {
    case (true, true):
      return "Your glasses firmware and app need updates before Codex display can start."
    case (true, false):
      return "Your glasses firmware needs an update before Codex display can start."
    case (false, true):
      return "The app on your glasses needs an update before Codex display can start."
    case (false, false):
      return ""
    }
  }

  private var updateFirmwareTitle: String {
    "Update firmware"
  }

  private var updateDATAppTitle: String {
    "Update app on glasses"
  }

  private func compatibilityActionButton(_ title: String, action: @escaping () -> Void) -> some View {
    SwiftUI.Button(action: action) {
      Text(title)
        .font(.body.weight(.semibold))
        .foregroundStyle(.white)
        .frame(maxWidth: .infinity)
        .padding(.vertical, 12)
        .background(Self.issueColor, in: Capsule())
    }
    .buttonStyle(.plain)
  }
}
