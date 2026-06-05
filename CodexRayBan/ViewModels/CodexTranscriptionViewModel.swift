import AVFoundation
import Foundation
import MWDATCore
import Observation

enum CodexMicrophonePermissionState: String {
  case unknown
  case granted
  case denied
  case unavailable

  var displayName: String {
    switch self {
    case .unknown:
      "Unknown"
    case .granted:
      "Allowed"
    case .denied:
      "Denied"
    case .unavailable:
      "Unavailable"
    }
  }
}

enum CodexTranscriptionError: LocalizedError {
  case missingAPIKey
  case systemMicrophoneDenied
  case recorderDidNotStart
  case missingRecording
  case badResponse(statusCode: Int, body: String)
  case missingTranscript
  case recordingTooLarge(bytes: Int64, maxBytes: Int64)

  var errorDescription: String? {
    switch self {
    case .missingAPIKey:
      "Sign in to Codex, or add an OpenAI API key in Settings to use voice input."
    case .systemMicrophoneDenied:
      "Microphone access is denied in iOS Settings."
    case .recorderDidNotStart:
      "Voice recording did not start."
    case .missingRecording:
      "No recording was available to transcribe."
    case .badResponse(let statusCode, let body):
      "Transcription failed with HTTP \(statusCode): \(body)"
    case .missingTranscript:
      "The transcription response did not include text."
    case .recordingTooLarge(let bytes, let maxBytes):
      "Voice recording is too large to transcribe (\(bytes / 1_048_576) MB, max \(maxBytes / 1_048_576) MB)."
    }
  }
}

@Observable
@MainActor
final class CodexTranscriptionViewModel {
  var isRecording = false
  var isTranscribing = false
  var selectedModel = "gpt-4o-mini-transcribe"
  var datMicrophonePermission: CodexMicrophonePermissionState = .unknown
  var activeInputName: String = "iPhone microphone"
  var audioLevel: Double = 0
  var lastTranscript: String = ""
  var errorMessage: String?

  @ObservationIgnored private let secureStore: CodexSecureStore
  @ObservationIgnored private let client: CodexTranscriptionClient
  @ObservationIgnored private let wearables: (any WearablesInterface)?
  @ObservationIgnored private var recorder: AVAudioRecorder?
  @ObservationIgnored private var audioEngine: AVAudioEngine?
  @ObservationIgnored private var recordingURL: URL?
  @ObservationIgnored private var meteringTask: Task<Void, Never>?
  @ObservationIgnored private var smoothedAudioLevel: Double = 0
  @ObservationIgnored private let maxRecordingDuration: TimeInterval = 120

  init(
    secureStore: CodexSecureStore = CodexSecureStore(),
    client: CodexTranscriptionClient = CodexTranscriptionClient(),
    wearables: (any WearablesInterface)? = nil
  ) {
    self.secureStore = secureStore
    self.client = client
    self.wearables = wearables
  }

  var hasAPIKey: Bool {
    (try? secureStore.loadTranscriptionAPIKey())?.isEmpty == false
  }

  var apiKeyPreview: String {
    guard let key = try? secureStore.loadTranscriptionAPIKey(), !key.isEmpty else {
      return "Missing"
    }

    let prefix = key.prefix(7)
    let suffix = key.suffix(4)
    return "\(prefix)...\(suffix)"
  }

  func saveAPIKey(_ key: String) throws {
    let trimmed = key.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else {
      throw CodexTranscriptionError.missingAPIKey
    }
    try secureStore.saveTranscriptionAPIKey(trimmed)
  }

  func clearAPIKey() throws {
    try secureStore.clearTranscriptionAPIKey()
  }

  func refreshPermissionStatus() async {
    guard let wearables else {
      datMicrophonePermission = .unavailable
      return
    }

    do {
      datMicrophonePermission = try await microphoneState(from: wearables.checkPermissionStatus(.microphone))
    } catch {
      datMicrophonePermission = .unavailable
    }
  }

  func requestDATMicrophonePermission() async {
    guard let wearables else {
      datMicrophonePermission = .unavailable
      return
    }

    do {
      datMicrophonePermission = try await microphoneState(from: wearables.requestPermission(.microphone))
    } catch {
      datMicrophonePermission = .unavailable
      errorMessage = error.localizedDescription
    }
  }

  func startRecording() async throws {
    guard !isRecording else {
      return
    }

    try await requestSystemMicrophonePermission()
    await refreshPermissionStatus()

    let session = AVAudioSession.sharedInstance()
    try session.setCategory(
      .playAndRecord,
      mode: .spokenAudio,
      options: [.allowBluetoothHFP, .defaultToSpeaker]
    )
    try session.setActive(true)
    try preferExternalInput(on: session)

    let url = FileManager.default.temporaryDirectory
      .appendingPathComponent("codex-voice-\(UUID().uuidString)")
      .appendingPathExtension("m4a")

    let settings: [String: Any] = [
      AVFormatIDKey: Int(kAudioFormatMPEG4AAC),
      AVSampleRateKey: 16_000,
      AVNumberOfChannelsKey: 1,
      AVEncoderAudioQualityKey: AVAudioQuality.high.rawValue,
    ]

    let recorder = try AVAudioRecorder(url: url, settings: settings)
    recorder.isMeteringEnabled = true
    guard recorder.record(forDuration: maxRecordingDuration) else {
      throw CodexTranscriptionError.recorderDidNotStart
    }

    self.recorder = recorder
    self.recordingURL = url
    self.audioLevel = 0
    self.smoothedAudioLevel = 0
    self.isRecording = true
    startMetering()
    self.errorMessage = nil
  }

  func stopAndTranscribe(codexAuthTokens: CodexAppServerAuthTokens? = nil) async throws -> String {
    let fileURL = try stopRecording()

    isTranscribing = true
    defer {
      isTranscribing = false
      try? FileManager.default.removeItem(at: fileURL)
    }

    let transcript: String
    if let codexAuthTokens {
      transcript = try await client.transcribeWithCodexSession(
        fileURL: fileURL,
        authTokens: codexAuthTokens
      )
    } else if let apiKey = try secureStore.loadTranscriptionAPIKey(), !apiKey.isEmpty {
      transcript = try await client.transcribe(
        fileURL: fileURL,
        apiKey: apiKey,
        model: selectedModel
      )
    } else {
      throw CodexTranscriptionError.missingAPIKey
    }

    lastTranscript = transcript
    return transcript
  }

  func cancelRecording() {
    stopMetering()
    recorder?.stop()
    recorder = nil
    audioEngine = nil
    isRecording = false
    audioLevel = 0
    smoothedAudioLevel = 0
    if let recordingURL {
      try? FileManager.default.removeItem(at: recordingURL)
    }
    recordingURL = nil
    try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
  }

  private func stopRecording() throws -> URL {
    guard let recorder, let recordingURL else {
      throw CodexTranscriptionError.missingRecording
    }

    stopMetering()
    recorder.stop()
    self.recorder = nil
    self.audioEngine = nil
    self.recordingURL = nil
    self.isRecording = false
    self.audioLevel = 0
    self.smoothedAudioLevel = 0
    try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
    return recordingURL
  }

  private func startMetering() {
    stopMetering()
    do {
      try startAudioEngineMetering()
      return
    } catch {
      audioEngine = nil
    }

    meteringTask = Task { [weak self] in
      while !Task.isCancelled {
        self?.updateAudioLevel()
        try? await Task.sleep(nanoseconds: 33_000_000)
      }
    }
  }

  private func stopMetering() {
    meteringTask?.cancel()
    meteringTask = nil
    audioEngine?.inputNode.removeTap(onBus: 0)
    audioEngine?.stop()
    audioEngine = nil
  }

  private func startAudioEngineMetering() throws {
    let engine = AVAudioEngine()
    let inputNode = engine.inputNode
    let format = inputNode.outputFormat(forBus: 0)
    guard format.channelCount > 0, format.sampleRate > 0 else {
      throw CodexTranscriptionError.recorderDidNotStart
    }

    inputNode.installTap(onBus: 0, bufferSize: 512, format: format) { buffer, _ in
      let targetLevel = Self.normalizedAudioPower(buffer: buffer)
      Task { @MainActor [weak self] in
        self?.acceptAudioLevel(targetLevel)
      }
    }

    engine.prepare()
    try engine.start()
    audioEngine = engine
  }

  private func updateAudioLevel() {
    guard isRecording, let recorder else {
      audioLevel = 0
      return
    }

    recorder.updateMeters()
    let targetLevel = Self.normalizedAudioPower(
      averagePower: recorder.averagePower(forChannel: 0),
      peakPower: recorder.peakPower(forChannel: 0)
    )
    acceptAudioLevel(targetLevel)
  }

  private func acceptAudioLevel(_ targetLevel: Double) {
    guard isRecording else {
      audioLevel = 0
      return
    }

    if targetLevel >= smoothedAudioLevel {
      smoothedAudioLevel = smoothedAudioLevel * 0.18 + targetLevel * 0.82
    } else {
      smoothedAudioLevel = smoothedAudioLevel * 0.72 + targetLevel * 0.28
    }
    audioLevel = min(max(smoothedAudioLevel, 0), 1)
  }

  nonisolated static func normalizedAudioPower(buffer: AVAudioPCMBuffer) -> Double {
    guard let channelData = buffer.floatChannelData else {
      return 0
    }
    let channelCount = Int(buffer.format.channelCount)
    let frameCount = Int(buffer.frameLength)
    guard channelCount > 0, frameCount > 0 else {
      return 0
    }

    var squareSum: Float = 0
    var peak: Float = 0
    var sampleCount = 0

    for channel in 0..<channelCount {
      let samples = channelData[channel]
      for frame in 0..<frameCount {
        let sample = samples[frame]
        squareSum += sample * sample
        peak = max(peak, abs(sample))
        sampleCount += 1
      }
    }

    guard sampleCount > 0 else {
      return 0
    }
    let rms = sqrt(squareSum / Float(sampleCount))
    let averagePower = 20 * log10(max(rms, 0.000_001))
    let peakPower = 20 * log10(max(peak, 0.000_001))
    return normalizedAudioPower(averagePower: averagePower, peakPower: peakPower)
  }

  nonisolated static func normalizedAudioPower(averagePower: Float, peakPower: Float) -> Double {
    let average = normalizedDecibels(averagePower, floor: -55, ceiling: -8)
    let peak = normalizedDecibels(peakPower, floor: -48, ceiling: -3)
    let blended = max(average * 0.78, peak * 0.92)
    return pow(min(max(blended, 0), 1), 0.62)
  }

  private nonisolated static func normalizedDecibels(_ power: Float, floor: Float, ceiling: Float) -> Double {
    guard power.isFinite, power > floor else {
      return 0
    }
    let clipped = min(max(power, floor), ceiling)
    return Double((clipped - floor) / (ceiling - floor))
  }

  private func requestSystemMicrophonePermission() async throws {
    switch AVAudioApplication.shared.recordPermission {
    case .granted:
      return
    case .denied:
      throw CodexTranscriptionError.systemMicrophoneDenied
    case .undetermined:
      let granted = await withCheckedContinuation { continuation in
        AVAudioApplication.requestRecordPermission { granted in
          continuation.resume(returning: granted)
        }
      }
      if !granted {
        throw CodexTranscriptionError.systemMicrophoneDenied
      }
    @unknown default:
      throw CodexTranscriptionError.systemMicrophoneDenied
    }
  }

  private func preferExternalInput(on session: AVAudioSession) throws {
    let preferredInput = session.availableInputs?.first { input in
      input.portType == .bluetoothHFP || input.portType == .headsetMic || input.portType == .usbAudio
    }

    if let preferredInput {
      try session.setPreferredInput(preferredInput)
      activeInputName = preferredInput.portName
    } else if let currentInput = session.currentRoute.inputs.first {
      activeInputName = currentInput.portName
    } else {
      activeInputName = "iPhone microphone"
    }
  }

  private func microphoneState(from status: PermissionStatus) -> CodexMicrophonePermissionState {
    switch status {
    case .granted:
      .granted
    case .denied:
      .denied
    @unknown default:
      .unknown
    }
  }
}

struct CodexTranscriptionClient {
  private let endpoint = URL(string: "https://api.openai.com/v1/audio/transcriptions")!
  private let codexEndpoint = CodexRemoteConstants.baseURL.appendingPathComponent("transcribe")
  private static let maxAudioFileBytes: Int64 = 8 * 1_024 * 1_024

  func transcribe(fileURL: URL, apiKey: String, model: String) async throws -> String {
    let boundary = "Boundary-\(UUID().uuidString)"
    let fileData = try Self.loadAudioData(fileURL)
    let body = Self.multipartBody(
      boundary: boundary,
      fields: [
        "model": model,
        "response_format": "json",
      ],
      fileField: "file",
      fileName: fileURL.lastPathComponent,
      mimeType: "audio/m4a",
      fileData: fileData
    )

    var request = URLRequest(url: endpoint)
    request.httpMethod = "POST"
    request.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
    request.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")

    let (data, response) = try await URLSession.shared.upload(for: request, from: body)
    return try Self.transcript(from: data, response: response)
  }

  func transcribeWithCodexSession(fileURL: URL, authTokens: CodexAppServerAuthTokens) async throws -> String {
    let boundary = "Boundary-\(UUID().uuidString)"
    let fileData = try Self.loadAudioData(fileURL)
    let body = Self.multipartBody(
      boundary: boundary,
      fields: [:],
      fileField: "file",
      fileName: fileURL.lastPathComponent,
      mimeType: "audio/m4a",
      fileData: fileData
    )

    var request = URLRequest(url: codexEndpoint)
    request.httpMethod = "POST"
    request.setValue("Bearer \(authTokens.accessToken)", forHTTPHeaderField: "Authorization")
    request.setValue(authTokens.chatgptAccountID, forHTTPHeaderField: "ChatGPT-Account-Id")
    request.setValue(CodexRemoteConstants.originator, forHTTPHeaderField: "originator")
    request.setValue(CodexRemoteConstants.userAgent, forHTTPHeaderField: "User-Agent")
    request.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")

    let (data, response) = try await URLSession.shared.upload(for: request, from: body)
    return try Self.transcript(from: data, response: response)
  }

  private static func transcript(from data: Data, response: URLResponse) throws -> String {
    guard let httpResponse = response as? HTTPURLResponse else {
      throw CodexTranscriptionError.badResponse(statusCode: -1, body: "Missing HTTP response")
    }
    guard (200..<300).contains(httpResponse.statusCode) else {
      let body = redactedBody(data)
      throw CodexTranscriptionError.badResponse(statusCode: httpResponse.statusCode, body: body)
    }
    let decoded = try JSONDecoder().decode(CodexTranscriptionResponse.self, from: data)
    let text = decoded.text.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !text.isEmpty else {
      throw CodexTranscriptionError.missingTranscript
    }
    return text
  }

  private static func loadAudioData(_ fileURL: URL) throws -> Data {
    let attributes = try FileManager.default.attributesOfItem(atPath: fileURL.path)
    let byteCount = (attributes[.size] as? NSNumber)?.int64Value ?? 0
    guard byteCount <= maxAudioFileBytes else {
      throw CodexTranscriptionError.recordingTooLarge(bytes: byteCount, maxBytes: maxAudioFileBytes)
    }
    return try Data(contentsOf: fileURL, options: .mappedIfSafe)
  }

  private static func redactedBody(_ data: Data) -> String {
    let raw = String(data: data.prefix(500), encoding: .utf8) ?? "Unreadable response body"
    let pattern = #""(access_token|refresh_token|api_key|Authorization|signature|file)"\s*:\s*"[^"]*""#
    guard let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else {
      return raw
    }
    let range = NSRange(raw.startIndex..<raw.endIndex, in: raw)
    return regex.stringByReplacingMatches(in: raw, range: range, withTemplate: #""$1":"[redacted]""#)
  }

  static func multipartBody(
    boundary: String,
    fields: [String: String],
    fileField: String,
    fileName: String,
    mimeType: String,
    fileData: Data
  ) -> Data {
    var body = Data()
    let lineBreak = "\r\n"

    for (name, value) in fields.sorted(by: { $0.key < $1.key }) {
      body.appendString("--\(boundary)\(lineBreak)")
      body.appendString("Content-Disposition: form-data; name=\"\(name)\"\(lineBreak)\(lineBreak)")
      body.appendString("\(value)\(lineBreak)")
    }

    body.appendString("--\(boundary)\(lineBreak)")
    body.appendString("Content-Disposition: form-data; name=\"\(fileField)\"; filename=\"\(fileName)\"\(lineBreak)")
    body.appendString("Content-Type: \(mimeType)\(lineBreak)\(lineBreak)")
    body.append(fileData)
    body.appendString(lineBreak)
    body.appendString("--\(boundary)--\(lineBreak)")
    return body
  }
}

private struct CodexTranscriptionResponse: Decodable {
  let text: String
}

private extension Data {
  mutating func appendString(_ string: String) {
    append(Data(string.utf8))
  }
}
