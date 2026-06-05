import MWDATCore
import MWDATDisplay
import Observation
import SwiftUI

@Observable
@MainActor
class DisplayViewModel {
  var isConnected: Bool = false
  var isSending: Bool = false
  var errorMessage: String?
  var requiresDATAppUpdate: Bool = false
  var didFailToStartSession: Bool = false

  @ObservationIgnored private let wearables: WearablesInterface
  @ObservationIgnored private var deviceSelector: AutoDeviceSelector
  @ObservationIgnored private var deviceSession: DeviceSession?
  @ObservationIgnored private var display: Display?
  @ObservationIgnored private var stateListenerToken: AnyListenerToken?
  @ObservationIgnored private var coreStateTask: Task<Void, Never>?
  @ObservationIgnored private var sessionErrorTask: Task<Void, Never>?
  @ObservationIgnored private var registrationTask: Task<Void, Never>?
  @ObservationIgnored private var displayStateTask: Task<Void, Never>?
  @ObservationIgnored private var petAnimationTask: Task<Void, Never>?
  @ObservationIgnored private var petAnimationState: CodexDisplayAppState?
  @ObservationIgnored private var petAnimationSignature: String?
  @ObservationIgnored private var displayStateContinuation: AsyncStream<DisplayState>.Continuation?
  @ObservationIgnored private var pendingAction: (() async -> Void)?

  init(wearables: WearablesInterface) {
    self.wearables = wearables
    self.deviceSelector = AutoDeviceSelector(wearables: wearables, filter: { $0.supportsDisplay() })
    observeRegistration()
  }

  isolated deinit {
    stateListenerToken = nil
    coreStateTask?.cancel()
    sessionErrorTask?.cancel()
    registrationTask?.cancel()
    displayStateTask?.cancel()
    petAnimationTask?.cancel()
  }

  // MARK: - Registration Observation

  private func observeRegistration() {
    registrationTask = Task { [weak self] in
      guard let wearables = self?.wearables else { return }
      for await state in wearables.registrationStateStream() {
        guard let self, !Task.isCancelled else { return }
        if state == .available || state == .unavailable {
          await self.resetDisplaySession()
        }
      }
    }
  }

  private func resetDisplaySession() async {
    await detachFromDisplay()
    deviceSelector = AutoDeviceSelector(wearables: wearables, filter: { $0.supportsDisplay() })
  }

  // MARK: - Public API

  /// Sends a display view to the glasses. Auto-attaches if not connected;
  /// the view is queued and sent once the display session is ready.
  func send(_ view: some DisplayableView) async {
    if let display, isConnected {
      await doSend(view, on: display)
      return
    }

    // Store as pending action — will fire once display is ready
    let sendableView = view
    pendingAction = { [weak self] in
      guard let self, let cap = self.display else { return }
      await self.doSend(sendableView, on: cap)
    }

    if display == nil {
      await attachToDisplay()
    }
  }

  private func doSend(_ view: some DisplayableView, on capability: Display) async {
    isSending = true
    defer { isSending = false }

    do {
      try await capability.send(view)
    } catch {
      let message = (error as? DisplayError)?.description ?? error.localizedDescription
      if message.localizedCaseInsensitiveContains("Superseded by new display request") {
        if CodexRuntimeEnvironment.isVerboseLoggingEnabled {
          NSLog("[Codex display] send superseded by newer request")
        }
        return
      }
      errorMessage = message
      if CodexRuntimeEnvironment.isVerboseLoggingEnabled {
        NSLog("[Codex display] send failed: %@", message)
      }
    }
  }

  // MARK: - Session Management

  func attachToDisplay() async {
    guard display == nil else { return }

    didFailToStartSession = false

    do {
      let devSession = try wearables.createSession(deviceSelector: deviceSelector)
      deviceSession = devSession

      let stateStream = devSession.stateStream()
      let errorStream = devSession.errorStream()
      coreStateTask = Task { [weak self] in
        for await sessionState in stateStream {
          guard let self, !Task.isCancelled else { return }
          switch sessionState {
          case .started:
            self.requiresDATAppUpdate = false
            self.didFailToStartSession = false
            await self.setupDisplay(on: devSession)
          case .stopping, .stopped:
            self.isConnected = false
            self.display = nil
          case .starting, .idle, .paused:
            break
          @unknown default:
            break
          }
        }
      }
      sessionErrorTask = Task { [weak self] in
        for await error in errorStream {
          guard let self, !Task.isCancelled else { return }
          self.handleSessionError(error)
        }
      }

      try devSession.start()
    } catch DeviceSessionError.datAppOnTheGlassesUpdateRequired {
      requiresDATAppUpdate = true
      didFailToStartSession = true
      errorMessage = DeviceSessionError.datAppOnTheGlassesUpdateRequired.localizedDescription
    } catch {
      requiresDATAppUpdate = false
      didFailToStartSession = true
      errorMessage = "Failed to create session: \(error.localizedDescription)"
    }
  }

  func clearSessionStartFailure() {
    didFailToStartSession = false
  }

  private func setupDisplay(on devSession: DeviceSession) async {
    guard display == nil else { return }

    do {
      let capability = try devSession.addDisplay()

      let (stateStream, continuation) = AsyncStream.makeStream(of: DisplayState.self)
      displayStateContinuation = continuation
      stateListenerToken = capability.statePublisher.listen { state in
        continuation.yield(state)
      }

      displayStateTask = Task { [weak self] in
        for await state in stateStream {
          guard let self, !Task.isCancelled else { return }
          switch state {
          case .starting:
            break
          case .started:
            self.isConnected = true
            // Execute pending action now that display is ready
            if let action = self.pendingAction {
              self.pendingAction = nil
              await action()
            }
          case .stopping:
            self.isConnected = false
          case .stopped:
            self.isConnected = false
            self.stateListenerToken = nil
            self.displayStateContinuation?.finish()
            self.displayStateContinuation = nil
            self.display = nil
            self.coreStateTask?.cancel()
            self.coreStateTask = nil
            self.deviceSession?.stop()
            self.deviceSession = nil
          }
        }
      }

      await capability.start()
      display = capability
    } catch {
      errorMessage = "Failed to start display: \(error.localizedDescription)"
    }
  }

  func sendReadyCard() async {
    await send(
      CodexDisplay.ready { [weak self] in
        Task { @MainActor in
          await self?.sendConfirmation("Display dismissed.")
        }
      }
    )
  }

  func sendHelloWorldCard() async {
    await send(
      CodexDisplay.helloWorld { [weak self] in
        Task { @MainActor in
          await self?.sendConfirmation("Hello world dismissed.")
        }
      }
    )
  }

  func sendAuthRequiredCard() async {
    await send(
      CodexDisplay.authRequired { [weak self] in
        Task { @MainActor in
          await self?.sendConfirmation("Continue sign-in on the iPhone.")
        }
      }
    )
  }

  func sendCodexStatusCard(title: String, detail: String) async {
    await send(
      CodexDisplay.codexStatus(title: title, detail: detail) { [weak self] in
        Task { @MainActor in
          await self?.sendConfirmation("Codex status dismissed.")
        }
      }
    )
  }

  func sendPetStatusCard(pet: CodexPet, state: CodexPetVisualState, detail: String) async {
    errorMessage = nil
    await send(
      CodexDisplay.petStatus(
        petName: pet.displayName,
        state: state.displayTitle,
        message: detail
      ) { [weak self] in
        Task { @MainActor in
          await self?.sendConfirmation("Pet dismissed.")
        }
      }
    )
  }

  func sendPetBubble(pet: CodexPet, message: String) async {
    await send(
      CodexDisplay.petBubble(
        imageURI: Self.petImageURL(for: pet),
        message: message
      ) { [weak self] in
        Task { @MainActor in
          await self?.sendConfirmation("Pet bubble dismissed.")
        }
      }
    )
  }

  func sendCodexDisplayApp(
    state: CodexDisplayAppState,
    actionHandler: @escaping @MainActor @Sendable (CodexDisplayAppAction) async -> Void
  ) async {
    errorMessage = nil

    var displayState = state
    if CodexDisplayAppScreen(rawValue: state.screen) == .pet {
      startPetAnimation(state: displayState, actionHandler: actionHandler)
      return
    }

    stopPetAnimation()

    if displayState.pet.imageURI == nil {
      let pet = CodexPet.pet(id: displayState.pet.id)
      displayState.pet.imageURI = Self.petImageURL(for: pet)
    }

    await send(
      CodexDisplayAppGlasses.app(state: displayState) { [weak self] action in
        Task { @MainActor in
          guard self != nil else { return }
          await actionHandler(action)
        }
      }
    )
  }

  private func startPetAnimation(
    state: CodexDisplayAppState,
    actionHandler: @escaping @MainActor @Sendable (CodexDisplayAppAction) async -> Void
  ) {
    petAnimationState = state
    let signature = petAnimationSignature(for: state)
    guard petAnimationTask == nil || petAnimationSignature != signature else {
      return
    }

    petAnimationTask?.cancel()
    petAnimationSignature = signature
    petAnimationTask = Task { [weak self] in
      await self?.runPetAnimation(state: state, actionHandler: actionHandler)
    }
  }

  private func stopPetAnimation() {
    petAnimationTask?.cancel()
    petAnimationTask = nil
    petAnimationState = nil
    petAnimationSignature = nil
  }

  private func runPetAnimation(
    state: CodexDisplayAppState,
    actionHandler: @escaping @MainActor @Sendable (CodexDisplayAppAction) async -> Void
  ) async {
    let visualState = CodexPetVisualState.desktopState(from: state.pet.state) ?? .idle
    let animation = CodexPetAnimation.animation(for: visualState)
    let frames = animation.frames.isEmpty
      ? [CodexPetFrame(row: 0, column: 0, duration: 1.0)]
      : animation.frames
    var frameIndex = 0

    while !Task.isCancelled {
      let frame = frames[frameIndex]
      var frameState = petAnimationState ?? state
      let pet = CodexPet.pet(id: frameState.pet.id)
      frameState.pet.imageURI = frameState.pet.imageURI ?? Self.petImageURL(for: pet)

      await send(
        CodexDisplayAppGlasses.app(state: frameState) { [weak self] action in
          Task { @MainActor in
            guard self != nil else { return }
            await actionHandler(action)
          }
        }
      )

      let nextIndex = frameIndex + 1
      if nextIndex >= frames.count, let loopStartIndex = animation.loopStartIndex, loopStartIndex < frames.count {
        frameIndex = loopStartIndex
      } else if nextIndex >= frames.count {
        frameIndex = 0
      } else {
        frameIndex = nextIndex
      }

      let delay = max(frame.duration, 0.18)
      try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
    }
  }

  private func petAnimationSignature(for state: CodexDisplayAppState) -> String {
    "\(state.pet.id):\(state.pet.state)"
  }

  static func petImageURL(for pet: CodexPet) -> String {
    pet.hostedImageURL
  }

  func sendConfirmation(_ message: String) async {
    await send(CodexDisplay.confirmation(message: message))
  }

  func detachFromDisplay() async {
    stopPetAnimation()
    stateListenerToken = nil
    displayStateContinuation?.finish()
    displayStateContinuation = nil
    displayStateTask?.cancel()
    displayStateTask = nil
    await display?.stop()
    display = nil
    coreStateTask?.cancel()
    coreStateTask = nil
    sessionErrorTask?.cancel()
    sessionErrorTask = nil
    deviceSession?.stop()
    deviceSession = nil
    isConnected = false
  }

  private func handleSessionError(_ error: DeviceSessionError) {
    requiresDATAppUpdate = error == .datAppOnTheGlassesUpdateRequired
    didFailToStartSession = true
    errorMessage = error.localizedDescription
  }
}

private extension CodexPetVisualState {
  var displayTitle: String {
    switch self {
    case .idle:
      "Idle"
    case .running, .runningLeft, .runningRight:
      "Running"
    case .thinking:
      "Thinking"
    case .waiting:
      "Waiting"
    case .review:
      "Ready"
    case .failed:
      "Needs attention"
    case .waving:
      "Waving"
    case .jumping:
      "Active"
    case .recording:
      "Listening"
    }
  }
}
