import SwiftUI
import UIKit
import WebKit

struct CodexDisplayAppHostScreen: View {
  var bridge: CodexDisplayAppBridge
  var authViewModel: CodexAuthViewModel
  var displayViewModel: DisplayViewModel
  var workspaceViewModel: CodexWorkspaceViewModel
  var transcriptionViewModel: CodexTranscriptionViewModel
  var hostID: String?
  var hostName: String

  @State private var refreshID = UUID()
  @State private var hasSentToGlasses = false
  @State private var errorMessage: String?

  var body: some View {
    List {
      Section("Display") {
        statusRow(
          title: "Session",
          value: displayViewModel.isConnected ? "Connected" : "Not connected",
          systemImage: displayViewModel.isConnected ? "checkmark.circle.fill" : "circle.dashed",
          color: displayViewModel.isConnected ? .green : .secondary
        )
        statusRow(
          title: "Remote host",
          value: hostName,
          systemImage: "desktopcomputer",
          color: .secondary
        )
        statusRow(
          title: "Current screen",
          value: currentScreenTitle,
          systemImage: currentScreenIcon,
          color: .secondary
        )

        Button {
          Task { await showWorkOnGlasses() }
        } label: {
          Label("Show Codex on glasses", systemImage: "terminal")
        }

        Button {
          Task { await showPetOnGlasses() }
        } label: {
          Label("Show pet on glasses", systemImage: "sparkle")
        }

        Button {
          Task { await sendDisplayAppToGlasses() }
        } label: {
          Label(hasSentToGlasses ? "Refresh glasses" : "Start glasses display", systemImage: "eyeglasses")
        }
      }

      Section("Pet") {
        Picker("Pet", selection: selectedPetID) {
          ForEach(CodexPet.builtIns) { pet in
            Text(pet.displayName).tag(pet.id)
          }
        }

        Picker("State", selection: selectedPetState) {
          ForEach(CodexPetVisualState.allCases, id: \.rawValue) { state in
            Text(petStateTitle(state)).tag(state)
          }
        }
      }

      if let displayError = displayViewModel.errorMessage {
        Section("Error") {
          Text(displayError)
            .foregroundStyle(.red)
          Button("Clear") {
            displayViewModel.errorMessage = nil
          }
        }
      }
    }
    .id(refreshID)
    .navigationTitle("Glasses Display")
    .navigationBarTitleDisplayMode(.inline)
    .toolbar {
      ToolbarItem(placement: .topBarTrailing) {
        Button {
          Task {
            await sendDisplayAppToGlasses()
          }
        } label: {
          Image(systemName: displayViewModel.isConnected ? "eyeglasses" : "eyeglasses")
        }
        .accessibilityLabel(hasSentToGlasses ? "Refresh glasses display" : "Show on glasses")
      }
    }
    .alert("Glasses display", isPresented: errorIsPresented) {
      Button("OK") {
        errorMessage = nil
      }
    } message: {
      Text(errorMessage ?? "The Meta display app could not handle that action.")
    }
    .task(id: workspaceRefreshKey) {
      await refreshWorkspace()
      await sendDisplayAppToGlasses()
    }
  }

  private var glassesDisplayState: CodexDisplayAppState {
    var state = bridge.state(
      from: workspaceViewModel,
      hostID: hostID,
      hostName: hostName
    )
    state.audioLevel = transcriptionViewModel.audioLevel
    return state
  }

  private var currentScreenTitle: String {
    switch bridge.screen {
    case .home:
      return "Codex home"
    case .project:
      return "Project"
    case .chat:
      return "Chat"
    case .chatActions:
      return "Chat menu"
    case .file:
      return "File"
    case .modelPicker:
      return "Model picker"
    case .pet:
      return "Pet"
    }
  }

  private var currentScreenIcon: String {
    switch bridge.screen {
    case .home:
      return "terminal"
    case .project:
      return "folder"
    case .chat:
      return "bubble.left.and.bubble.right"
    case .chatActions:
      return "ellipsis.circle"
    case .file:
      return "doc.text"
    case .modelPicker:
      return "slider.horizontal.3"
    case .pet:
      return "sparkle"
    }
  }

  private var selectedPetID: Binding<String> {
    Binding {
      workspaceViewModel.selectedPet.id
    } set: { id in
      workspaceViewModel.selectedPet = CodexPet.pet(id: id)
      refreshID = UUID()
      if bridge.screen == .pet {
        Task { await sendDisplayAppToGlasses() }
      }
    }
  }

  private var selectedPetState: Binding<CodexPetVisualState> {
    Binding {
      workspaceViewModel.petState
    } set: { state in
      workspaceViewModel.petState = state
      refreshID = UUID()
      if bridge.screen == .pet {
        Task { await sendDisplayAppToGlasses() }
      }
    }
  }

  private var errorIsPresented: Binding<Bool> {
    Binding {
      errorMessage != nil
    } set: { isPresented in
      if !isPresented {
        errorMessage = nil
      }
    }
  }

  private func petStateTitle(_ state: CodexPetVisualState) -> String {
    switch state {
    case .idle:
      return "Idle"
    case .running, .runningLeft, .runningRight:
      return "Running"
    case .thinking:
      return "Thinking"
    case .waiting:
      return "Waiting"
    case .review:
      return "Ready"
    case .failed:
      return "Needs attention"
    case .waving:
      return "Waving"
    case .jumping:
      return "Active"
    case .recording:
      return "Listening"
    }
  }

  @ViewBuilder
  private func statusRow(title: String, value: String, systemImage: String, color: Color) -> some View {
    HStack(spacing: 12) {
      Image(systemName: systemImage)
        .foregroundStyle(color)
        .frame(width: 24)
      VStack(alignment: .leading, spacing: 2) {
        Text(title)
        Text(value)
          .font(.caption)
          .foregroundStyle(.secondary)
          .lineLimit(1)
          .truncationMode(.middle)
      }
    }
  }

  private func handle(_ envelope: CodexDisplayAppActionEnvelope) async {
    do {
      try await bridge.handle(
        envelope.action,
        workspace: workspaceViewModel,
        transcribe: transcribe
      )
      refreshID = UUID()
      await sendDisplayAppToGlasses()
    } catch {
      errorMessage = error.localizedDescription
    }
  }

  private func sendDisplayAppToGlasses() async {
    hasSentToGlasses = true
    await displayViewModel.sendCodexDisplayApp(state: glassesDisplayState) { action in
      await handle(CodexDisplayAppActionEnvelope(action: action))
    }
  }

  private func showWorkOnGlasses() async {
    await handle(CodexDisplayAppActionEnvelope(action: .setMode(.work)))
  }

  private func showPetOnGlasses() async {
    await handle(CodexDisplayAppActionEnvelope(action: .setMode(.pet)))
  }

  private func refreshWorkspace() async {
    if authViewModel.session.isRemoteEnrolled && !authViewModel.session.remoteTokenIsFresh {
      await authViewModel.refreshRemoteToken()
    }

    if authViewModel.session.isSignedIn {
      await authViewModel.refreshHosts()
    }

    await workspaceViewModel.refresh(
      session: authViewModel.session,
      environments: authViewModel.environments,
      preferredEnvironmentID: hostID,
      authTokenProvider: {
        try await authViewModel.appServerAuthTokens()
      }
    )
  }

  private var workspaceRefreshKey: String {
    [
      authViewModel.session.isSignedIn ? "signed-in" : "signed-out",
      authViewModel.session.remoteClientID ?? "no-client",
      hostID ?? "auto-host",
    ].joined(separator: ":")
  }

  private func transcribe(chatID: String?) async throws -> CodexDisplayAppTranscriptionResult {
    if transcriptionViewModel.isRecording {
      bridge.isTranscribing = true
      workspaceViewModel.petState = .thinking
      refreshID = UUID()
      await sendDisplayAppToGlasses()
      defer {
        bridge.isTranscribing = false
      }

      let authTokens = try? await authViewModel.appServerAuthTokens()
      let text = try await transcriptionViewModel.stopAndTranscribe(codexAuthTokens: authTokens)
      return CodexDisplayAppTranscriptionResult(text: text, isRecording: false)
    }

    try await transcriptionViewModel.startRecording()
    return CodexDisplayAppTranscriptionResult(text: "", isRecording: true)
  }

}

struct CodexDisplayAppWebView: UIViewRepresentable {
  var state: CodexDisplayAppState
  var refreshID: UUID
  var onAction: (CodexDisplayAppActionEnvelope) -> Void

  func makeCoordinator() -> Coordinator {
    Coordinator(onAction: onAction)
  }

  func makeUIView(context: Context) -> WKWebView {
    let configuration = WKWebViewConfiguration()
    configuration.userContentController.add(context.coordinator, name: "codexDisplayAction")

    let webView = WKWebView(frame: .zero, configuration: configuration)
    webView.navigationDelegate = context.coordinator
    webView.scrollView.isScrollEnabled = false
    webView.scrollView.bounces = false
    context.coordinator.webView = webView
    context.coordinator.pendingState = state

    if let url = Bundle.main.url(forResource: "codex-display-app", withExtension: "html") {
      webView.loadFileURL(url, allowingReadAccessTo: url.deletingLastPathComponent())
    } else {
      webView.loadHTMLString(Self.missingResourceHTML, baseURL: nil)
    }

    return webView
  }

  func updateUIView(_ webView: WKWebView, context: Context) {
    context.coordinator.onAction = onAction
    context.coordinator.pendingState = state
    context.coordinator.postStateIfReady()
  }

  static func dismantleUIView(_ webView: WKWebView, coordinator: Coordinator) {
    webView.configuration.userContentController.removeScriptMessageHandler(forName: "codexDisplayAction")
  }

  final class Coordinator: NSObject, WKNavigationDelegate, WKScriptMessageHandler {
    weak var webView: WKWebView?
    var onAction: (CodexDisplayAppActionEnvelope) -> Void
    var pendingState: CodexDisplayAppState?
    private var didFinishLoad = false

    init(onAction: @escaping (CodexDisplayAppActionEnvelope) -> Void) {
      self.onAction = onAction
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
      didFinishLoad = true
      postStateIfReady()
    }

    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
      do {
        let data = try Self.data(from: message.body)
        let envelope = try JSONDecoder().decode(CodexDisplayAppActionEnvelope.self, from: data)
        onAction(envelope)
      } catch {
        #if DEBUG
        if CodexRuntimeEnvironment.isVerboseLoggingEnabled {
          NSLog("[CodexDisplayAppWebView] Ignored action: \(error)")
        }
        #endif
      }
    }

    func postStateIfReady() {
      guard didFinishLoad, let webView, let pendingState else {
        return
      }

      do {
        let data = try JSONEncoder().encode(pendingState)
        guard let json = String(data: data, encoding: .utf8) else {
          return
        }
        let script = """
        window.CodexDisplayNativeBridge = true;
        window.postMessage({ type: 'codex:set-state', state: \(json) }, '*');
        """
        webView.evaluateJavaScript(script)
      } catch {
        #if DEBUG
        if CodexRuntimeEnvironment.isVerboseLoggingEnabled {
          NSLog("[CodexDisplayAppWebView] Failed to post state: \(error)")
        }
        #endif
      }
    }

    private static func data(from body: Any) throws -> Data {
      if let string = body as? String {
        return Data(string.utf8)
      }
      if JSONSerialization.isValidJSONObject(body) {
        return try JSONSerialization.data(withJSONObject: body)
      }
      throw CodexDisplayAppActionError.invalidPayload("Unsupported WKScriptMessage body")
    }
  }

  private static let missingResourceHTML = """
  <!doctype html>
  <html>
    <head>
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <style>
        body {
          margin: 0;
          display: grid;
          min-height: 100vh;
          place-items: center;
          background: #f8f8f6;
          color: #151515;
          font-family: -apple-system, BlinkMacSystemFont, sans-serif;
        }
      </style>
    </head>
    <body>Missing codex-display-app.html</body>
  </html>
  """
}
