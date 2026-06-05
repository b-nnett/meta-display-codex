import MWDATCore
import SwiftUI
import UIKit

private enum AppTab: Hashable {
  case codex
  case settings
}

@MainActor
private final class DisplayBackgroundTask {
  private var identifier: UIBackgroundTaskIdentifier = .invalid

  func beginIfNeeded(isDisplayConnected: Bool) {
    guard isDisplayConnected, identifier == .invalid else {
      return
    }

    identifier = UIApplication.shared.beginBackgroundTask(withName: "Codex glasses display") { [weak self] in
      Task { @MainActor in
        self?.end()
      }
    }
  }

  func end() {
    guard identifier != .invalid else {
      return
    }

    let currentIdentifier = identifier
    identifier = .invalid
    UIApplication.shared.endBackgroundTask(currentIdentifier)
  }
}

@main
struct CodexRayBanApp: App {
  @Environment(\.scenePhase) private var scenePhase

  @State private var wearablesViewModel: WearablesViewModel
  @State private var displayViewModel: DisplayViewModel
  @State private var authViewModel: CodexAuthViewModel
  @State private var workspaceViewModel: CodexWorkspaceViewModel
  @State private var transcriptionViewModel: CodexTranscriptionViewModel
  @State private var displayAppBridge = CodexDisplayAppBridge()
  @State private var displayBackgroundTask = DisplayBackgroundTask()
  @State private var audioDisplayUpdateTask: Task<Void, Never>?
  @State private var selectedTab: AppTab = .codex
  @State private var isAutoLaunchingDisplay = false
  @AppStorage("codex.selected.remote.host.id") private var selectedRemoteHostID = ""

  init() {
    do {
      try Wearables.configure()
    } catch {
      #if DEBUG
      if CodexRuntimeEnvironment.isVerboseLoggingEnabled {
        NSLog("[CodexRayBan] Failed to configure Wearables SDK: \(error)")
      }
      #endif
    }

    let wearables = Wearables.shared
    self._wearablesViewModel = State(wrappedValue: WearablesViewModel(wearables: wearables))
    self._displayViewModel = State(wrappedValue: DisplayViewModel(wearables: wearables))
    self._authViewModel = State(wrappedValue: CodexAuthViewModel())
    self._workspaceViewModel = State(wrappedValue: CodexWorkspaceViewModel())
    self._transcriptionViewModel = State(wrappedValue: CodexTranscriptionViewModel(wearables: wearables))
  }

  var body: some Scene {
    WindowGroup {
      TabView(selection: $selectedTab) {
        NavigationStack {
          CodexHomeView(
            displayViewModel: displayViewModel,
            authViewModel: authViewModel,
            workspaceViewModel: workspaceViewModel,
            transcriptionViewModel: transcriptionViewModel,
            showChatOnGlasses: showChatForActiveChatOnGlasses,
            showPetOnGlasses: showPetForActiveChatOnGlasses
          )
        }
        .tabItem {
          Label("Codex", systemImage: "terminal")
        }
        .tag(AppTab.codex)

        NavigationStack {
          SettingsView(
            viewModel: SettingsViewModel(
              registrationState: wearablesViewModel.registrationState,
              deviceItemStates: wearablesViewModel.deviceItemStates,
              requiresFirmwareUpdate: wearablesViewModel.requiresFirmwareUpdate,
              requiresDATAppUpdate: displayViewModel.requiresDATAppUpdate,
              connectGlasses: {
                Task {
                  await wearablesViewModel.connectGlasses()
                }
              },
              disconnectGlasses: {
                Task {
                  await wearablesViewModel.disconnectGlasses()
                }
              },
              openFirmwareUpdate: {
                wearablesViewModel.openFirmwareUpdate()
              },
              openDATGlassesAppUpdate: {
                wearablesViewModel.openDATGlassesAppUpdate()
              }
            ),
            authViewModel: authViewModel,
            displayViewModel: displayViewModel,
            transcriptionViewModel: transcriptionViewModel,
            displayAppBridge: displayAppBridge,
            workspaceViewModel: workspaceViewModel,
            displayHostID: selectedRemoteHost?.envID,
            displayHostName: selectedRemoteHost?.displayName ?? "No host"
          )
        }
        .tabItem {
          Label("Settings", systemImage: "gearshape")
        }
        .tag(AppTab.settings)
      }
      .onChange(of: displayViewModel.didFailToStartSession) { _, didFailToStartSession in
        if didFailToStartSession {
          selectedTab = .settings
          displayViewModel.clearSessionStartFailure()
        }
      }
      .task {
        await autoLaunchCodexOnGlasses()
      }
      .onChange(of: scenePhase) { _, phase in
        switch phase {
        case .active:
          displayBackgroundTask.end()
          Task {
            await autoLaunchCodexOnGlasses()
          }
        case .background:
          displayBackgroundTask.beginIfNeeded(isDisplayConnected: displayViewModel.isConnected)
          Task {
            await keepDisplayOpenInBackground()
          }
        case .inactive:
          break
        @unknown default:
          break
        }
      }
      .onChange(of: connectedGlassesKey) { _, key in
        guard !key.isEmpty else { return }
        Task {
          await autoLaunchCodexOnGlasses()
        }
      }
      .onChange(of: workspaceViewModel.activeChat?.id) { _, chatID in
        guard chatID != nil else { return }
        Task {
          await showChatForActiveChatOnGlasses()
        }
      }
      .onChange(of: glassesDisplayRefreshKey) { _, _ in
        guard displayAppBridge.screen == .pet || displayAppBridge.screen == .chat else {
          return
        }
        guard displayViewModel.isConnected || !connectedGlassesKey.isEmpty else {
          return
        }
        guard !displayViewModel.isSending else {
          return
        }
        Task {
          await sendDisplayAppToGlasses()
        }
      }
      .onChange(of: transcriptionViewModel.isRecording) { _, isRecording in
        if isRecording {
          startAudioDisplayUpdates()
        } else {
          stopAudioDisplayUpdates()
          Task {
            await sendDisplayAppToGlasses()
          }
        }
      }
      .alert("Error", isPresented: $wearablesViewModel.showError) {
        Button("OK") { wearablesViewModel.dismissError() }
      } message: {
        Text(wearablesViewModel.errorMessage)
      }

      RegistrationView(viewModel: wearablesViewModel)
    }
  }

  private var selectedRemoteHost: CodexEnvironment? {
    if let match = authViewModel.environments.first(where: { $0.envID == selectedRemoteHostID }) {
      return match
    }
    return authViewModel.environments.first(where: \.online) ?? authViewModel.environments.first
  }

  private var connectedGlassesKey: String {
    wearablesViewModel.deviceItemStates
      .filter { $0.linkState == .connected && $0.compatibility != .deviceUpdateRequired }
      .map { "\($0.identifier)" }
      .sorted()
      .joined(separator: ",")
  }

  private var selectedDisplayHostID: String? {
    if !selectedRemoteHostID.isEmpty {
      return selectedRemoteHostID
    }
    return selectedRemoteHost?.envID
  }

  private var glassesDisplayRefreshKey: String {
    [
      displayAppBridge.mode.rawValue,
      displayAppBridge.screen.rawValue,
      workspaceViewModel.selectedPet.id,
      workspaceViewModel.petState.rawValue,
      workspaceViewModel.activeChat?.id ?? "",
      workspaceViewModel.activeChat?.isStreaming == true ? "streaming" : "idle",
      workspaceViewModel.activeChat?.messages.suffix(2).map(glassesMessageSignature).joined(separator: "|") ?? "",
      transcriptionViewModel.isRecording ? "recording" : "",
      transcriptionViewModel.isTranscribing ? "transcribing" : "",
    ].joined(separator: ":")
  }

  private var glassesDisplayState: CodexDisplayAppState {
    var state = displayAppBridge.state(
      from: workspaceViewModel,
      hostID: selectedDisplayHostID,
      hostName: selectedRemoteHost?.displayName ?? "No host"
    )
    state.audioLevel = transcriptionViewModel.audioLevel
    return state
  }

  private func glassesMessageSignature(_ message: CodexChatMessage) -> String {
    [
      message.id,
      message.parts.map(glassesPartSignature).joined(separator: ","),
    ].joined(separator: "=")
  }

  private func glassesPartSignature(_ part: CodexMessagePart) -> String {
    switch part {
    case .text(let id, let text), .reasoning(let id, let text):
      return "\(id):\(text.count)"
    case .tool(let tool):
      return "\(tool.id):\(tool.status):\(tool.detail.count)"
    case .fileGroup(let group):
      return "\(group.id):\(group.files.count)"
    case .file(let file):
      return "\(file.id):\(file.detail.count):\(file.diff?.count ?? 0)"
    case .todos(let id, let items):
      return "\(id):\(items.map { "\($0.id)-\($0.isDone)" }.joined(separator: ","))"
    }
  }

  private func autoLaunchCodexOnGlasses() async {
    guard !CodexRuntimeEnvironment.isRunningTests else {
      return
    }
    guard !isAutoLaunchingDisplay else {
      return
    }
    guard displayViewModel.isConnected || !connectedGlassesKey.isEmpty else {
      return
    }

    isAutoLaunchingDisplay = true
    defer {
      isAutoLaunchingDisplay = false
    }

    let preferredMode: CodexDisplayAppMode = .work
    let preferredScreen: CodexDisplayAppScreen = workspaceViewModel.activeChat == nil ? .home : .chat
    if displayAppBridge.mode != preferredMode || displayAppBridge.screen != preferredScreen {
      displayAppBridge.mode = preferredMode
      displayAppBridge.screen = preferredScreen
      displayAppBridge.selectedChatID = workspaceViewModel.activeChat?.id
      displayAppBridge.selectedProjectID = workspaceViewModel.activeChat?.projectPath
    }

    await refreshDisplayWorkspace()
    await sendDisplayAppToGlasses()
  }

  private func refreshDisplayWorkspace() async {
    if authViewModel.session.isRemoteEnrolled && !authViewModel.session.remoteTokenIsFresh {
      let refreshed = await authViewModel.refreshRemoteToken()
      guard refreshed else {
        return
      }
    }

    if authViewModel.session.isSignedIn {
      await authViewModel.refreshHosts()
    }

    await workspaceViewModel.refresh(
      session: authViewModel.session,
      environments: authViewModel.environments,
      preferredEnvironmentID: selectedDisplayHostID,
      authTokenProvider: {
        try await authViewModel.appServerAuthTokens()
      }
    )
  }

  private func handleDisplayAction(_ action: CodexDisplayAppAction) async {
    logDisplay("action received \(action.diagnosticsSummary)")
    if case .startTranscription = action, transcriptionViewModel.isRecording {
      displayAppBridge.isTranscribing = true
      workspaceViewModel.petState = .thinking
      logDisplay("transcribe finish immediate redraw \(action.diagnosticsSummary)")
      await sendDisplayAppToGlasses()
    }
    do {
      try await displayAppBridge.handle(
        action,
        workspace: workspaceViewModel,
        transcribe: transcribe
      )
      if action.switchesGlassesToPetAfterHandling {
        try await displayAppBridge.handle(.setMode(.pet), workspace: workspaceViewModel)
      }
      await sendDisplayAppToGlasses()
      logDisplay("action completed \(action.diagnosticsSummary)")
    } catch {
      displayViewModel.errorMessage = error.localizedDescription
      logDisplay("action failed \(action.diagnosticsSummary) error=\(error.localizedDescription)")
      await sendDisplayAppToGlasses()
    }
  }

  private func sendDisplayAppToGlasses() async {
    await displayViewModel.sendCodexDisplayApp(state: glassesDisplayState) { action in
      await handleDisplayAction(action)
    }
  }

  private func logDisplay(_ message: String) {
    if CodexRuntimeEnvironment.isVerboseLoggingEnabled {
      NSLog("[Codex display app] %@", message)
    }
  }

  private func startAudioDisplayUpdates() {
    guard audioDisplayUpdateTask == nil else {
      return
    }

    audioDisplayUpdateTask = Task { @MainActor in
      while !Task.isCancelled {
        guard transcriptionViewModel.isRecording else {
          break
        }

        if displayAppBridge.screen == .chat,
           displayViewModel.isConnected || !connectedGlassesKey.isEmpty,
           !displayViewModel.isSending {
          await sendDisplayAppToGlasses()
        }

        try? await Task.sleep(nanoseconds: 80_000_000)
      }
      audioDisplayUpdateTask = nil
    }
  }

  private func stopAudioDisplayUpdates() {
    audioDisplayUpdateTask?.cancel()
    audioDisplayUpdateTask = nil
  }

  private func transcribe(chatID: String?) async throws -> CodexDisplayAppTranscriptionResult {
    if transcriptionViewModel.isRecording {
      logDisplay("transcribe finish start chat=\(chatID ?? "missing")")
      let didAlreadyShowTranscribing = displayAppBridge.isTranscribing && workspaceViewModel.petState == .thinking
      displayAppBridge.isTranscribing = true
      workspaceViewModel.petState = .thinking
      if !didAlreadyShowTranscribing {
        await sendDisplayAppToGlasses()
      }
      defer {
        displayAppBridge.isTranscribing = false
      }

      let authTokens = try? await authViewModel.appServerAuthTokens()
      let text = try await transcriptionViewModel.stopAndTranscribe(codexAuthTokens: authTokens)
      logDisplay("transcribe finish success chat=\(chatID ?? "missing") chars=\(text.count)")
      return CodexDisplayAppTranscriptionResult(text: text, isRecording: false)
    }

    logDisplay("transcribe recording start chat=\(chatID ?? "missing")")
    try await transcriptionViewModel.startRecording()
    return CodexDisplayAppTranscriptionResult(text: "", isRecording: true)
  }

  private func showPetForActiveChatOnGlasses() async {
    guard displayViewModel.isConnected || !connectedGlassesKey.isEmpty else {
      return
    }

    do {
      try await displayAppBridge.handle(.setMode(.pet), workspace: workspaceViewModel)
    } catch {
      displayViewModel.errorMessage = error.localizedDescription
    }
    await sendDisplayAppToGlasses()
  }

  private func showChatForActiveChatOnGlasses() async {
    guard displayViewModel.isConnected || !connectedGlassesKey.isEmpty else {
      return
    }
    guard let activeChat = workspaceViewModel.activeChat else {
      return
    }

    displayAppBridge.mode = .work
    displayAppBridge.screen = .chat
    displayAppBridge.selectedChatID = activeChat.id
    displayAppBridge.selectedProjectID = activeChat.projectPath
    displayAppBridge.isComposingNewChat = false
    await sendDisplayAppToGlasses()
  }

  private func keepDisplayOpenInBackground() async {
    guard displayViewModel.isConnected else {
      return
    }

    if workspaceViewModel.activeChat != nil {
      await showChatForActiveChatOnGlasses()
    } else {
      await sendDisplayAppToGlasses()
    }
  }
}

extension CodexDisplayAppAction {
  var switchesGlassesToPetAfterHandling: Bool {
    switch self {
    case .openChat:
      return true
    case .openProject,
         .openFile,
         .startTranscription,
         .acceptTranscript,
         .discardTranscript,
         .newChat,
         .setMode,
         .sendMessage,
         .updateDraft,
         .setComposerExpanded,
         .setShowAllPinnedChats,
         .setShowAllChats,
         .setShowAllProjects,
         .setShowAllProjectChats,
         .setShowAllMessages,
         .setPetBubbleExpanded,
         .loadOlderTurns,
         .interruptTurn,
         .togglePinned,
         .archiveChat,
         .setModel,
         .setScreen:
      return false
    }
  }
}
