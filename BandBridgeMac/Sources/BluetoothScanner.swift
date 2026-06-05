import Foundation
import CoreBluetooth
import CryptoKit
import Security

enum BluetoothLogLevel: String {
  case info
  case success
  case warning
  case error
}

enum AirShieldProbeError: Error {
  case randomChallengeUnavailable
}

struct BluetoothLogEntry: Identifiable, Hashable {
  let id = UUID()
  var date = Date()
  var level: BluetoothLogLevel
  var line: String
}

final class BluetoothScanner: NSObject, ObservableObject {
  static let exactBandName = BandScanner.exactBandName

  @Published private(set) var bluetoothStateDescription = "Starting Bluetooth"
  @Published private(set) var isBluetoothReady = false
  @Published private(set) var isScanning = false
  @Published private(set) var discoveredPeripherals: [DiscoveredPeripheral] = []
  @Published private(set) var connectedPeripheralID: UUID?
  @Published private(set) var connectionDescription = "Disconnected"
  @Published private(set) var serviceRows: [ServiceRow] = []
  @Published private(set) var logEntries: [BluetoothLogEntry] = []
  @Published private(set) var gestureEntries: [ForwardedGestureEvent] = []
  @Published private(set) var rawFrameCount = 0
  @Published private(set) var decodedFrameCount = 0
  @Published private(set) var secureLinkDescription = "Not started"
  @Published private(set) var airShieldValidationDescription = "No validation yet"
  @Published private(set) var airShieldIdentityDescription = "No identity imported"
  @Published private(set) var airShieldAuthCandidateDescription = "No auth candidates"
  @Published private(set) var airShieldAuthGateDescription = "No auth gate loaded"
  @Published private(set) var reconnectDescription = "Idle"
  @Published private(set) var isL2CAPOpen = false
  @Published private(set) var canSendAirShieldEnableTrust = false
  @Published private(set) var canSendEncryptedEndLinkSetup = false
  @Published private(set) var canSendEncryptedGestureEnable = false
  @Published var selectedPeripheralID: UUID?
  @Published var selectedIdentitySlot: AirShieldIdentitySlot = .acdcAppPrivateKey
  @Published var autoConnectExactBand = true
  @Published var autoConnectLikelyPairingBand = false
  @Published var autoOpenDetectedL2CAP = true
  @Published var dumpRawFrames = true
  @Published var attemptDataXHandshake = true

  let logFilePath: String
  let gestureEventFilePath: String
  let gestureSocketEndpoint: String
  let gestureWebSocketEndpoint: String
  let gestureHTTPEndpoint: String
  let gestureLANHTTPEndpoint: String
  let sessionEventFilePath: String
  let sessionSummaryFilePath: String
  let directWriteTriggerFilePath: String
  let rescanTriggerFilePath: String

  private let sessionID = UUID()
  private var central: CBCentralManager!
  private var peripheralsByID: [UUID: CBPeripheral] = [:]
  private var discoveryByID: [UUID: DiscoveredPeripheral] = [:]
  private var loggedDiscoveryByID: [UUID: (date: Date, rssi: Int, advertisementSummary: String)] = [:]
  private var hasAutoConnectedToExactBand = false
  private var hasAutoConnectedToLikelyBand = false
  private var manualDisconnectRequested = false
  private var reconnectAttemptCount = 0
  private let maximumReconnectAttempts = 8
  private var consecutiveConnectTimeoutCount = 0
  private let maximumConsecutiveConnectTimeouts = 3
  private var pendingReconnectWorkItem: DispatchWorkItem?
  private var pendingConnectTimeoutWorkItem: DispatchWorkItem?
  private var pendingLikelyAutoConnectWorkItem: DispatchWorkItem?
  private var attemptedLikelyPeripheralIDs = Set<UUID>()
  private var timeoutScheduledReconnectPeripheralIDs = Set<UUID>()
  private var openedL2CAPPSMs = Set<UInt16>()
  private var l2capInputStream: InputStream?
  private var l2capOutputStream: OutputStream?
  private var dataXDecoder = DataXFrameDecoder()
  private var gattDataXDecoder = DataXFrameDecoder()
  private var airShieldEncryptedFrameDecoder = AirShieldEncryptedFrameDecoder()
  private var decryptedDataXDecoder = DataXFrameDecoder()
  private weak var gattDataXWritePeripheral: CBPeripheral?
  private var gattDataXWriteCharacteristic: CBCharacteristic?
  private let airShieldSession = AirShieldSession()
  private var airShieldIdentityMaterial: AirShieldIdentityMaterial?
  private var pendingEnableTrustFramesByCandidateID: [String: Data] = [:]
  private var loadedEnableTrustGateCandidateID: String?
  private var loadedEnableTrustGateFrameFingerprint: String?
  private var airShieldHandshakeProbeSent = false
  private var pendingAirShieldProbeFrame: Data?
  private var pendingAirShieldProbeLogFields: [String: Any]?
  private var airShieldProbeRetryCount = 0
  private let maximumAirShieldProbeRetries = 20
  private var pendingAirShieldProbeRetryWorkItem: DispatchWorkItem?
  private var directWriteDiagnosticID: UUID?
  private var directWriteTriggerTimer: Timer?
  private var encryptedEndLinkSetupSent = false
  private let eventForwarder: EventForwarder
  private let sessionRecorder: SessionRecorder
  private let logHandle: FileHandle?
  private let isoFormatter = ISO8601DateFormatter()

  override init() {
    let logDirectory = FileManager.default.homeDirectoryForCurrentUser
      .appendingPathComponent("Library/Logs/CodexBandBridge", isDirectory: true)
    try? FileManager.default.createDirectory(at: logDirectory, withIntermediateDirectories: true)
    let logURL = logDirectory.appendingPathComponent("bluetooth-events.jsonl")
    if !FileManager.default.fileExists(atPath: logURL.path) {
      FileManager.default.createFile(atPath: logURL.path, contents: nil)
    }
    let directWriteTriggerURL = logDirectory.appendingPathComponent("direct-write-request.json")
    let rescanTriggerURL = logDirectory.appendingPathComponent("rescan-request.json")
    let eventForwarder = EventForwarder(logDirectory: logDirectory)
    let sessionRecorder = SessionRecorder(sessionID: sessionID, logDirectory: logDirectory)
    self.eventForwarder = eventForwarder
    self.sessionRecorder = sessionRecorder
    self.gestureEventFilePath = eventForwarder.eventFilePath
    self.gestureSocketEndpoint = eventForwarder.socketEndpoint
    self.gestureWebSocketEndpoint = eventForwarder.webSocketEndpoint
    self.gestureHTTPEndpoint = eventForwarder.httpEndpoint
    self.gestureLANHTTPEndpoint = eventForwarder.lanHTTPEndpoint
    self.sessionEventFilePath = sessionRecorder.eventFilePath
    self.sessionSummaryFilePath = sessionRecorder.summaryFilePath
    self.directWriteTriggerFilePath = directWriteTriggerURL.path
    self.rescanTriggerFilePath = rescanTriggerURL.path
    self.logFilePath = logURL.path
    self.logHandle = try? FileHandle(forWritingTo: logURL)
    self.logHandle?.seekToEndOfFile()
    super.init()
    loadStoredAirShieldIdentity()
    self.central = CBCentralManager(delegate: self, queue: .main)
    sessionRecorder.record("app.started", ["bundle_id": "com.example.codexbandbridge"])
    startDirectWriteTriggerWatcher()
    sessionRecorder.record("control.direct_write_trigger_ready", ["path": directWriteTriggerFilePath])
    sessionRecorder.record("control.rescan_trigger_ready", ["path": rescanTriggerFilePath])
    log(.info, "App started with bundle id com.example.codexbandbridge session=\(sessionID.uuidString)")
  }

  deinit {
    directWriteTriggerTimer?.invalidate()
    logHandle?.closeFile()
  }

  var selectedPeripheralName: String {
    guard let selectedPeripheralID else {
      return "None"
    }
    return discoveryByID[selectedPeripheralID]?.displayName ?? selectedPeripheralID.uuidString
  }

  var hasLikelyBandCandidate: Bool {
    discoveryByID.values.contains { $0.isCandidate }
  }

  func startScanningIfPossible() {
    guard isBluetoothReady else {
      return
    }
    startScan()
  }

  func startScan() {
    guard isBluetoothReady else {
      log(.warning, "Cannot scan until Bluetooth is powered on")
      return
    }
    discoveredPeripherals = []
    discoveryByID = [:]
    peripheralsByID = [:]
    loggedDiscoveryByID = [:]
    hasAutoConnectedToExactBand = false
    hasAutoConnectedToLikelyBand = false
    openedL2CAPPSMs = []
    dataXDecoder.reset()
    gattDataXDecoder.reset()
    airShieldEncryptedFrameDecoder.reset()
    decryptedDataXDecoder.reset()
    gattDataXWritePeripheral = nil
    gattDataXWriteCharacteristic = nil
    airShieldSession.reset()
    pendingEnableTrustFramesByCandidateID = [:]
    airShieldHandshakeProbeSent = false
    pendingAirShieldProbeFrame = nil
    pendingAirShieldProbeLogFields = nil
    airShieldProbeRetryCount = 0
    cancelPendingAirShieldProbeRetry()
    encryptedEndLinkSetupSent = false
    rawFrameCount = 0
    decodedFrameCount = 0
    secureLinkDescription = "Not started"
    airShieldValidationDescription = "No validation yet"
    airShieldAuthCandidateDescription = "No auth candidates"
    refreshEnableTrustGateAvailability()
    canSendAirShieldEnableTrust = false
    canSendEncryptedEndLinkSetup = false
    canSendEncryptedGestureEnable = false
    reconnectDescription = "Idle"
    isL2CAPOpen = false
    reconnectAttemptCount = 0
    consecutiveConnectTimeoutCount = 0
    manualDisconnectRequested = false
    cancelPendingReconnect()
    cancelPendingConnectTimeout()
    cancelPendingLikelyAutoConnect()
    timeoutScheduledReconnectPeripheralIDs.removeAll()
    selectedPeripheralID = nil
    isScanning = true
    log(.info, "Scanning for BLE peripherals exactTarget=\(Self.exactBandName)")
    sessionRecorder.record("ble.scan_started", ["exact_target": Self.exactBandName])
    central.scanForPeripherals(withServices: nil, options: [
      CBCentralManagerScanOptionAllowDuplicatesKey: false
    ])
  }

  func stopScan() {
    central.stopScan()
    isScanning = false
    cancelPendingLikelyAutoConnect()
    sessionRecorder.record("ble.scan_stopped")
    log(.info, "Stopped scanning")
  }

  func connectSelectedPeripheral() {
    guard let selectedPeripheralID, let peripheral = peripheralsByID[selectedPeripheralID] else {
      log(.warning, "No selected peripheral to connect")
      return
    }
    manualDisconnectRequested = false
    cancelPendingReconnect()
    cancelPendingConnectTimeout()
    stopScan()
    connectionDescription = "Connecting to \(displayName(for: peripheral))"
    sessionRecorder.recordConnection("ble.connect_requested", peripheral: peripheral, name: displayName(for: peripheral))
    log(.info, "Connecting to \(displayName(for: peripheral)) id=\(peripheral.identifier.uuidString)")
    central.connect(peripheral, options: nil)
    scheduleConnectTimeout(for: peripheral, reason: "connect_requested")
  }

  func connectStrongestLikelyBand() {
    guard let item = discoveryByID.values
      .filter({ $0.isCandidate && !attemptedLikelyPeripheralIDs.contains($0.id) })
      .sorted(by: { lhs, rhs in
        if lhs.candidatePriority != rhs.candidatePriority {
          return lhs.candidatePriority > rhs.candidatePriority
        }
        return lhs.rssi > rhs.rssi
      })
      .first else {
      log(.warning, "No likely band candidate to connect")
      return
    }
    attemptedLikelyPeripheralIDs.insert(item.id)
    selectedPeripheralID = item.id
    sessionRecorder.record("ble.manual_likely_candidate_selected", [
      "name": item.displayName,
      "rssi": item.rssi,
      "is_exact_band": item.isExactBand,
      "peripheral_id": item.id.uuidString,
      "advertisement": item.advertisementSummary
    ])
    log(.info, "Selected strongest likely band name=\(item.displayName) rssi=\(item.rssi)")
    connectSelectedPeripheral()
  }

  func disconnect() {
    guard let connectedPeripheralID, let peripheral = peripheralsByID[connectedPeripheralID] else {
      return
    }
    manualDisconnectRequested = true
    cancelPendingReconnect()
    cancelPendingConnectTimeout()
    timeoutScheduledReconnectPeripheralIDs.removeAll()
    closeL2CAPStreams(reason: "manual disconnect")
    central.cancelPeripheralConnection(peripheral)
  }

  func rediscoverServices() {
    guard let connectedPeripheralID, let peripheral = peripheralsByID[connectedPeripheralID] else {
      log(.warning, "No connected peripheral for service discovery")
      return
    }
    serviceRows = []
    log(.info, "Discovering services on \(displayName(for: peripheral))")
    peripheral.discoverServices(nil)
  }

  func openL2CAPChannel(psmText: String) {
    guard let connectedPeripheralID, let peripheral = peripheralsByID[connectedPeripheralID] else {
      log(.warning, "No connected peripheral for L2CAP")
      return
    }

    guard let psm = L2CAPSession.parsePSMText(psmText) else {
      log(.error, "Invalid PSM value: \(psmText)")
      return
    }

    log(.info, "Opening L2CAP channel psm=\(psm) on \(displayName(for: peripheral))")
    peripheral.openL2CAPChannel(CBL2CAPPSM(psm))
  }

  func sendAirShieldHandshakeProbe() {
    sendAirShieldRequestEncryptionProbe()
  }

  func sendAirShieldHandshakeProbeDirectWriteDiagnostic() {
    guard directWriteDiagnosticID == nil else {
      log(.warning, "Direct L2CAP write diagnostic is already running")
      return
    }
    guard let output = l2capOutputStream else {
      sessionRecorder.record("l2cap.direct_write_diagnostic_blocked", ["reason": "no_output_stream"])
      log(.error, "Direct L2CAP write diagnostic blocked: no output stream")
      return
    }
    guard output.streamStatus == .open || output.streamStatus == .writing else {
      sessionRecorder.record("l2cap.direct_write_diagnostic_blocked", [
        "reason": "stream_not_open",
        "stream_status": output.streamStatus.rawValue,
        "stream_status_description": L2CAPSession.streamStatusDescription(output.streamStatus)
      ])
      log(.error, "Direct L2CAP write diagnostic blocked: output stream not open")
      return
    }

    do {
      let prepared = try prepareAirShieldRequestEncryptionProbeIfNeeded()
      let data = prepared.frame
      let diagnosticID = UUID()
      let diagnosticLabel = "airshield.request_encryption.probe.direct_write_diagnostic"
      directWriteDiagnosticID = diagnosticID
      cancelPendingAirShieldProbeRetry()
      secureLinkDescription = "Direct write diagnostic running"
      sessionRecorder.record("l2cap.direct_write_diagnostic_started", [
        "label": diagnosticLabel,
        "bytes_requested": data.count,
        "frame_fingerprint": Self.shortSHA256Fingerprint(data),
        "stream_status": output.streamStatus.rawValue,
        "stream_status_description": L2CAPSession.streamStatusDescription(output.streamStatus),
        "has_space_available": output.hasSpaceAvailable
      ])
      log(.warning, "Starting direct L2CAP write diagnostic bytes=\(data.count) hasSpace=\(output.hasSpaceAvailable)")

      DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) { [weak self, weak output] in
        guard let self, self.directWriteDiagnosticID == diagnosticID else {
          return
        }
        self.directWriteDiagnosticID = nil
        self.secureLinkDescription = "Direct write diagnostic timed out"
        self.sessionRecorder.record("l2cap.direct_write_diagnostic_timeout", [
          "label": diagnosticLabel,
          "timeout_seconds": 2.0,
          "bytes_requested": data.count,
          "frame_fingerprint": Self.shortSHA256Fingerprint(data),
          "action": "close_l2cap_streams"
        ])
        self.log(.error, "Direct L2CAP write diagnostic timed out; closing L2CAP streams")
        output?.close()
        self.closeL2CAPStreams(reason: "direct write diagnostic timeout")
      }

      DispatchQueue.global(qos: .userInitiated).async { [weak self, weak output] in
        guard let output else {
          DispatchQueue.main.async {
            self?.sessionRecorder.record("l2cap.direct_write_diagnostic_finished", [
              "label": diagnosticLabel,
              "bytes_requested": data.count,
              "bytes_written": 0,
              "frame_fingerprint": Self.shortSHA256Fingerprint(data),
              "reason": "output_stream_released"
            ])
          }
          return
        }
        var offset = 0
        let bytesWritten = data.withUnsafeBytes { rawBuffer -> Int in
          guard let baseAddress = rawBuffer.bindMemory(to: UInt8.self).baseAddress else {
            return 0
          }
          while offset < data.count {
            let written = output.write(baseAddress.advanced(by: offset), maxLength: data.count - offset)
            if written <= 0 {
              return offset
            }
            offset += written
          }
          return offset
        }
        let streamStatus = output.streamStatus
        let streamError = output.streamError?.localizedDescription
        DispatchQueue.main.async { [weak self] in
          guard let self else { return }
          let wasCurrentDiagnostic = self.directWriteDiagnosticID == diagnosticID
          if wasCurrentDiagnostic {
            self.directWriteDiagnosticID = nil
          }
          self.sessionRecorder.record("l2cap.direct_write_diagnostic_finished", [
            "label": diagnosticLabel,
            "bytes_requested": data.count,
            "bytes_written": bytesWritten,
            "frame_fingerprint": Self.shortSHA256Fingerprint(data),
            "stream_status": streamStatus.rawValue,
            "stream_status_description": L2CAPSession.streamStatusDescription(streamStatus),
            "stream_error": streamError ?? "nil",
            "completed_before_timeout": wasCurrentDiagnostic
          ])
          if bytesWritten == data.count {
            self.sessionRecorder.recordL2CAPTX(
              byteCount: bytesWritten,
              data: self.dumpRawFrames ? data : nil,
              label: diagnosticLabel
            )
            self.airShieldHandshakeProbeSent = true
            self.pendingAirShieldProbeFrame = nil
            self.pendingAirShieldProbeLogFields = nil
            self.secureLinkDescription = "Direct write diagnostic sent probe"
            self.log(.success, "Direct L2CAP write diagnostic wrote \(bytesWritten)/\(data.count) bytes")
          } else if wasCurrentDiagnostic {
            self.secureLinkDescription = "Direct write diagnostic incomplete"
            self.log(.error, "Direct L2CAP write diagnostic wrote \(bytesWritten)/\(data.count) bytes")
          }
        }
      }
    } catch {
      secureLinkDescription = "Direct write diagnostic failed"
      sessionRecorder.record("l2cap.direct_write_diagnostic_blocked", [
        "reason": "probe_encode_failed",
        "error": String(describing: error)
      ])
      log(.error, "Could not prepare direct L2CAP write diagnostic: \(error)")
    }
  }

  func startDirectWriteTriggerWatcher() {
    directWriteTriggerTimer?.invalidate()
    let timer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in
      self?.consumeDirectWriteTriggerIfReady()
      self?.consumeRescanTriggerIfReady()
    }
    timer.tolerance = 0.25
    directWriteTriggerTimer = timer
  }

  func consumeDirectWriteTriggerIfReady() {
    let path = directWriteTriggerFilePath
    guard FileManager.default.fileExists(atPath: path) else {
      return
    }
    guard isL2CAPOpen, directWriteDiagnosticID == nil else {
      return
    }
    let url = URL(fileURLWithPath: path)
    let payload = (try? String(contentsOf: url, encoding: .utf8))
      .map { String($0.prefix(256)) }
    do {
      try FileManager.default.removeItem(at: url)
    } catch {
      sessionRecorder.record("control.direct_write_trigger_blocked", [
        "path": path,
        "reason": "remove_failed",
        "error": error.localizedDescription
      ])
      log(.error, "Direct Write trigger blocked: could not remove request file")
      return
    }
    var fields: [String: Any] = ["path": path]
    if let payload, !payload.isEmpty {
      fields["payload_prefix"] = payload
    }
    sessionRecorder.record("control.direct_write_trigger_received", fields)
    log(.warning, "Direct Write trigger file consumed")
    sendAirShieldHandshakeProbeDirectWriteDiagnostic()
  }

  func consumeRescanTriggerIfReady() {
    let path = rescanTriggerFilePath
    guard FileManager.default.fileExists(atPath: path) else {
      return
    }
    let url = URL(fileURLWithPath: path)
    let payload = (try? String(contentsOf: url, encoding: .utf8))
      .map { String($0.prefix(256)) }
    do {
      try FileManager.default.removeItem(at: url)
    } catch {
      sessionRecorder.record("control.rescan_trigger_blocked", [
        "path": path,
        "reason": "remove_failed",
        "error": error.localizedDescription
      ])
      log(.error, "Rescan trigger blocked: could not remove request file")
      return
    }

    var fields: [String: Any] = ["path": path]
    if let payload, !payload.isEmpty {
      fields["payload_prefix"] = payload
    }
    sessionRecorder.record("control.rescan_trigger_received", fields)
    log(.warning, "Rescan trigger file consumed")

    guard isBluetoothReady else {
      sessionRecorder.record("control.rescan_trigger_blocked", [
        "path": path,
        "reason": "bluetooth_not_ready",
        "state": bluetoothStateDescription
      ])
      log(.error, "Rescan trigger blocked: Bluetooth is not ready")
      return
    }

    if isScanning {
      central.stopScan()
      isScanning = false
    }
    if let connectedPeripheralID, let peripheral = peripheralsByID[connectedPeripheralID] {
      manualDisconnectRequested = true
      closeL2CAPStreams(reason: "rescan trigger")
      central.cancelPeripheralConnection(peripheral)
      self.connectedPeripheralID = nil
    }
    manualDisconnectRequested = false
    startScan()
  }

  func sendEncryptedGestureEnable() {
    sendEncryptedGestureEnableIfValidated()
  }

  func sendEncryptedEndLinkSetup() {
    sendEncryptedEndLinkSetupIfValidated()
  }

  func loadAirShieldAuthGate(pathText: String) {
    let trimmed = pathText.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else {
      log(.warning, "No auth gate path supplied")
      return
    }

    let path = (trimmed as NSString).expandingTildeInPath
    do {
      let data = try Data(contentsOf: URL(fileURLWithPath: path))
      let gate = try AirShieldEnableTrustGate.parse(data: data)
      loadedEnableTrustGateCandidateID = gate.candidateID
      loadedEnableTrustGateFrameFingerprint = gate.frameFingerprint
      refreshEnableTrustGateAvailability()
      sessionRecorder.recordAirShieldEnableTrustGateLoaded([
        "path": path,
        "candidate_id": gate.candidateID,
        "frame_fingerprint": loadedEnableTrustGateFrameFingerprint ?? "nil",
        "can_send": canSendAirShieldEnableTrust
      ])
      log(.success, "Loaded EnableTrust auth gate candidate=\(gate.candidateID)")
    } catch {
      loadedEnableTrustGateCandidateID = nil
      loadedEnableTrustGateFrameFingerprint = nil
      refreshEnableTrustGateAvailability()
      sessionRecorder.record("airshield.identity.enable_trust_gate_load_failed", [
        "path": path,
        "error": String(describing: error)
      ])
      log(.error, "EnableTrust auth gate load failed: \(error)")
    }
  }

  func sendAirShieldEnableTrustIfGated() {
    guard let candidateID = loadedEnableTrustGateCandidateID else {
      sessionRecorder.record("airshield.identity.enable_trust.tx_blocked", [
        "reason": "no_auth_gate_loaded"
      ])
      log(.warning, "EnableTrust auth blocked: no gate loaded")
      return
    }
    guard let frame = pendingEnableTrustFramesByCandidateID[candidateID] else {
      sessionRecorder.record("airshield.identity.enable_trust.tx_blocked", [
        "reason": "candidate_not_staged",
        "candidate_id": candidateID
      ])
      log(.warning, "EnableTrust auth blocked: candidate not staged")
      refreshEnableTrustGateAvailability()
      return
    }
    let frameFingerprint = Self.shortSHA256Fingerprint(frame)
    if let expected = loadedEnableTrustGateFrameFingerprint,
       expected != "nil",
       !AirShieldEnableTrustGate.fingerprintMatches(expected, frameFingerprint) {
      sessionRecorder.record("airshield.identity.enable_trust.tx_blocked", [
        "reason": "frame_fingerprint_mismatch",
        "candidate_id": candidateID,
        "expected_frame_fingerprint": expected,
        "staged_frame_fingerprint": frameFingerprint
      ])
      log(.error, "EnableTrust auth blocked: gate frame fingerprint mismatch")
      refreshEnableTrustGateAvailability()
      return
    }
    guard canSendAirShieldEnableTrust else {
      sessionRecorder.record("airshield.identity.enable_trust.tx_blocked", [
        "reason": "gate_not_sendable",
        "candidate_id": candidateID,
        "l2cap_open": isL2CAPOpen
      ])
      log(.warning, "EnableTrust auth blocked until L2CAP is open and candidate is staged")
      refreshEnableTrustGateAvailability()
      return
    }

    let readyFields: [String: Any] = [
      "candidate_id": candidateID,
      "frame_length": frame.count,
      "frame_fingerprint": frameFingerprint
    ]
    sessionRecorder.recordAirShieldEnableTrustReady(readyFields)
    if sendL2CAPData(frame, label: "airshield.identity.enable_trust.gated_candidate") {
      sessionRecorder.recordAirShieldEnableTrustSent(readyFields)
      canSendAirShieldEnableTrust = false
      airShieldAuthGateDescription = "Auth gate sent \(candidateID)"
      secureLinkDescription = "EnableTrust auth candidate sent"
    }
  }

  func importAirShieldIdentity(base64: String) {
    importAirShieldIdentity(base64: base64, source: "paste")
  }

  func importAirShieldIdentity(pathText: String) {
    let trimmed = pathText.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else {
      log(.warning, "No identity file path supplied")
      return
    }

    let path = (trimmed as NSString).expandingTildeInPath
    do {
      let base64 = try String(contentsOfFile: path, encoding: .utf8)
      importAirShieldIdentity(base64: base64, source: "file", sourcePath: path)
    } catch {
      sessionRecorder.record("airshield.identity.import_failed", [
        "source": "file",
        "path": path,
        "error": String(describing: error)
      ])
      log(.error, "AirShield identity file import failed: \(error)")
    }
  }

  private func importAirShieldIdentity(base64: String, source: String, sourcePath: String? = nil) {
    do {
      let material = try AirShieldIdentityMaterial.imported(slot: selectedIdentitySlot, base64: base64)
      try AirShieldIdentityKeychain.save(material)
      airShieldIdentityMaterial = material
      pendingEnableTrustFramesByCandidateID = [:]
      airShieldAuthCandidateDescription = "No auth candidates"
      refreshEnableTrustGateAvailability()
      updateAirShieldIdentityDescription()
      var fields = airShieldIdentityLogFields(material)
      fields["source"] = source
      if let sourcePath {
        fields["source_path"] = sourcePath
      }
      sessionRecorder.recordAirShieldIdentityImported(fields)
      log(.success, "Imported AirShield identity \(material.summary) source=\(source)")
    } catch {
      var fields: [String: Any] = [
        "source": source,
        "error": String(describing: error)
      ]
      if let sourcePath {
        fields["source_path"] = sourcePath
      }
      sessionRecorder.record("airshield.identity.import_failed", fields)
      log(.error, "AirShield identity import failed: \(error)")
    }
  }

  func clearAirShieldIdentity() {
    do {
      try AirShieldIdentityKeychain.delete()
      airShieldIdentityMaterial = nil
      pendingEnableTrustFramesByCandidateID = [:]
      airShieldAuthCandidateDescription = "No auth candidates"
      refreshEnableTrustGateAvailability()
      updateAirShieldIdentityDescription()
      sessionRecorder.record("airshield.identity.cleared")
      log(.warning, "Cleared imported AirShield identity")
    } catch {
      sessionRecorder.record("airshield.identity.clear_failed", ["error": String(describing: error)])
      log(.error, "AirShield identity clear failed: \(error)")
    }
  }
}

extension BluetoothScanner: CBCentralManagerDelegate {
  func centralManagerDidUpdateState(_ central: CBCentralManager) {
    switch central.state {
    case .poweredOn:
      bluetoothStateDescription = "Bluetooth powered on"
      isBluetoothReady = true
      log(.success, "Bluetooth powered on")
      startScan()
    case .poweredOff:
      bluetoothStateDescription = "Bluetooth powered off"
      isBluetoothReady = false
      isScanning = false
      closeL2CAPStreams(reason: "Bluetooth powered off")
      log(.error, "Bluetooth powered off")
    case .unauthorized:
      bluetoothStateDescription = "Bluetooth permission is not authorized"
      isBluetoothReady = false
      log(.error, "Bluetooth unauthorized")
    case .unsupported:
      bluetoothStateDescription = "Bluetooth is unsupported on this Mac"
      isBluetoothReady = false
      log(.error, "Bluetooth unsupported")
    case .resetting:
      bluetoothStateDescription = "Bluetooth is resetting"
      isBluetoothReady = false
      log(.warning, "Bluetooth resetting")
    case .unknown:
      bluetoothStateDescription = "Bluetooth state unknown"
      isBluetoothReady = false
      log(.warning, "Bluetooth state unknown")
    @unknown default:
      bluetoothStateDescription = "Bluetooth state changed"
      isBluetoothReady = false
      log(.warning, "Bluetooth state changed to unknown future value")
    }
  }

  func centralManager(
    _ central: CBCentralManager,
    didDiscover peripheral: CBPeripheral,
    advertisementData: [String: Any],
    rssi RSSI: NSNumber
  ) {
    peripheralsByID[peripheral.identifier] = peripheral
    let name = peripheral.name ?? advertisementData[CBAdvertisementDataLocalNameKey] as? String
    let summary = Self.advertisementSummary(advertisementData)
    let candidate = Self.isLikelyBand(name: name, advertisementSummary: summary)
    let exactBand = Self.isExactTargetBand(name: name)
    let item = DiscoveredPeripheral(
      id: peripheral.identifier,
      name: name,
      rssi: RSSI.intValue,
      advertisementSummary: summary,
      isCandidate: candidate,
      isExactBand: exactBand
    )
    discoveryByID[item.id] = item
    sessionRecorder.recordDiscovery(item)
    discoveredPeripherals = discoveryByID.values.sorted {
      if $0.candidatePriority != $1.candidatePriority {
        return $0.candidatePriority > $1.candidatePriority
      }
      if $0.isCandidate != $1.isCandidate {
        return $0.isCandidate
      }
      if $0.displayName == $1.displayName {
        return $0.rssi > $1.rssi
      }
      return $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending
    }

    if item.isCandidate {
      if selectedPeripheralID == nil {
        selectedPeripheralID = item.id
      }
      if item.isExactBand {
        selectedPeripheralID = item.id
        if autoConnectExactBand && connectedPeripheralID == nil && !hasAutoConnectedToExactBand {
          hasAutoConnectedToExactBand = true
          cancelPendingLikelyAutoConnect()
          log(.success, "Exact target band matched; auto-connecting to \(item.displayName)")
          connectSelectedPeripheral()
        }
      } else if autoConnectLikelyPairingBand && connectedPeripheralID == nil && !hasAutoConnectedToLikelyBand {
        scheduleLikelyAutoConnect()
      }
      if shouldLogDiscovery(item) {
        log(.success, "Candidate discovered name=\(item.displayName) rssi=\(item.rssi) id=\(item.id.uuidString) adv=\(summary)")
      }
    } else if shouldLogDiscovery(item) {
      log(.info, "Discovered name=\(item.displayName) rssi=\(item.rssi) id=\(item.id.uuidString) adv=\(summary)")
    }
  }

  func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
    connectedPeripheralID = peripheral.identifier
    connectionDescription = "Connected to \(displayName(for: peripheral))"
    reconnectAttemptCount = 0
    consecutiveConnectTimeoutCount = 0
    reconnectDescription = "Connected"
    timeoutScheduledReconnectPeripheralIDs.remove(peripheral.identifier)
    cancelPendingReconnect()
    cancelPendingConnectTimeout()
    peripheral.delegate = self
    sessionRecorder.recordConnection("ble.connected", peripheral: peripheral, name: displayName(for: peripheral))
    log(.success, "Connected to \(displayName(for: peripheral)) id=\(peripheral.identifier.uuidString)")
    peripheral.discoverServices(nil)
  }

  func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
    cancelPendingConnectTimeout()
    connectionDescription = "Failed to connect"
    sessionRecorder.recordConnection(
      "ble.connect_failed",
      peripheral: peripheral,
      name: displayName(for: peripheral),
      error: errorDescription(error)
    )
    log(.error, "Failed to connect to \(displayName(for: peripheral)): \(errorDescription(error))")
    if timeoutScheduledReconnectPeripheralIDs.remove(peripheral.identifier) == nil {
      scheduleReconnectIfNeeded(for: peripheral, reason: "connect_failed", error: error)
    }
  }

  func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
    cancelPendingConnectTimeout()
    if connectedPeripheralID == peripheral.identifier {
      connectedPeripheralID = nil
    }
    closeL2CAPStreams(reason: "BLE disconnect")
    connectionDescription = "Disconnected"
    sessionRecorder.recordConnection(
      "ble.disconnected",
      peripheral: peripheral,
      name: displayName(for: peripheral),
      error: errorDescription(error)
    )
    log(.warning, "Disconnected from \(displayName(for: peripheral)): \(errorDescription(error))")
    if timeoutScheduledReconnectPeripheralIDs.remove(peripheral.identifier) == nil {
      scheduleReconnectIfNeeded(for: peripheral, reason: "disconnect", error: error)
    }
    if autoConnectLikelyPairingBand,
       attemptedLikelyPeripheralIDs.contains(peripheral.identifier),
       !manualDisconnectRequested {
      hasAutoConnectedToLikelyBand = false
      DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) { [weak self] in
        guard let self, self.connectedPeripheralID == nil, !self.isScanning else {
          return
        }
        self.sessionRecorder.record("ble.likely_sweep_rescan", [
          "after_peripheral_id": peripheral.identifier.uuidString,
          "name": self.displayName(for: peripheral)
        ])
        self.startScan()
      }
    }
  }
}

extension BluetoothScanner: CBPeripheralDelegate {
  func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
    if let error {
      log(.error, "Service discovery failed: \(error.localizedDescription)")
      return
    }
    guard let services = peripheral.services else {
      log(.warning, "Service discovery returned no services")
      return
    }
    sessionRecorder.recordServices(services)
    log(.success, "Discovered \(services.count) services")
    if attemptedLikelyPeripheralIDs.contains(peripheral.identifier),
       !isExactKnownBand(peripheral),
       !Self.hasTargetBandServices(services) {
      sessionRecorder.record("ble.likely_candidate_rejected", [
        "peripheral_id": peripheral.identifier.uuidString,
        "name": displayName(for: peripheral),
        "services": services.map { $0.uuid.uuidString },
        "reason": "missing_meta_band_services"
      ])
      log(.warning, "Likely candidate rejected after service discovery; missing Meta band services")
      central.cancelPeripheralConnection(peripheral)
      return
    }
    for service in services {
      serviceRows.append(ServiceRow(title: "Service \(service.uuid.uuidString)", detail: "Discovering characteristics"))
      peripheral.discoverCharacteristics(nil, for: service)
    }
  }

  func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
    if let error {
      log(.error, "Characteristic discovery failed for \(service.uuid.uuidString): \(error.localizedDescription)")
      return
    }
    guard let characteristics = service.characteristics else {
      return
    }

    log(.success, "Service \(service.uuid.uuidString) has \(characteristics.count) characteristics")
    for characteristic in characteristics {
      let properties = GattSession.propertiesDescription(characteristic.properties)
      sessionRecorder.recordCharacteristic(characteristic, service: service, properties: properties)
      log(.info, "Characteristic \(characteristic.uuid.uuidString) service=\(service.uuid.uuidString) properties=\(properties)")
      serviceRows.append(ServiceRow(
        title: "Characteristic \(characteristic.uuid.uuidString)",
        detail: "service=\(service.uuid.uuidString) properties=\(properties)"
      ))
      if characteristic.properties.contains(.read) {
        peripheral.readValue(for: characteristic)
      }
      if Self.isDADADataXCharacteristic(characteristic),
         characteristic.properties.contains(.writeWithoutResponse) || characteristic.properties.contains(.write) {
        gattDataXWritePeripheral = peripheral
        gattDataXWriteCharacteristic = characteristic
        sessionRecorder.record("gatt.datax.write_characteristic_ready", [
          "service_uuid": service.uuid.uuidString,
          "characteristic_uuid": characteristic.uuid.uuidString,
          "properties": properties
        ])
        log(.success, "GATT DataX fallback write characteristic ready \(characteristic.uuid.uuidString)")
      }
      if characteristic.properties.contains(.notify) || characteristic.properties.contains(.indicate) {
        peripheral.setNotifyValue(true, for: characteristic)
      }
      peripheral.discoverDescriptors(for: characteristic)
    }
  }

  func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
    if let error {
      sessionRecorder.recordCharacteristicError(characteristic, service: characteristic.service, error: error)
      log(.error, "Read/update failed for \(characteristic.uuid.uuidString): \(error.localizedDescription)")
      return
    }
    guard let value = characteristic.value else {
      log(.info, "Value update for \(characteristic.uuid.uuidString): empty")
      return
    }
    let hex = value.hexString
    sessionRecorder.recordCharacteristicValue(characteristic, service: characteristic.service, value: value)
    if Self.isDADADataXCharacteristic(characteristic) {
      let frames = gattDataXDecoder.append(value)
      sessionRecorder.recordGATTDataXRX(
        characteristic: characteristic,
        service: characteristic.service,
        value: value,
        decodedFrameCount: frames.count
      )
      if !frames.isEmpty {
        handleDecodedDataXFrames(frames, source: "gatt.dada")
      }
    }
    let ascii = value.printableASCII
    var suffix = "hex=\(hex)"
    if !ascii.isEmpty {
      suffix += " ascii=\"\(ascii)\""
    }
    if let little = GattSession.psmFromLittleEndianValue(value) {
      let big = (UInt16(value[0]) << 8) | UInt16(value[1])
      suffix += " possiblePSM(le=\(little), be=\(big))"
      openDetectedL2CAPPSM(little, source: characteristic.uuid.uuidString)
    }
    log(.info, "Value \(characteristic.uuid.uuidString): \(suffix)")
  }

  func peripheral(_ peripheral: CBPeripheral, didDiscoverDescriptorsFor characteristic: CBCharacteristic, error: Error?) {
    if let error {
      log(.warning, "Descriptor discovery failed for \(characteristic.uuid.uuidString): \(error.localizedDescription)")
      return
    }
    for descriptor in characteristic.descriptors ?? [] {
      log(.info, "Descriptor \(descriptor.uuid.uuidString) for characteristic \(characteristic.uuid.uuidString)")
      peripheral.readValue(for: descriptor)
    }
  }

  func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor descriptor: CBDescriptor, error: Error?) {
    if let error {
      log(.warning, "Descriptor read failed \(descriptor.uuid.uuidString): \(error.localizedDescription)")
      return
    }
    let value = String(describing: descriptor.value ?? "nil")
    log(.info, "Descriptor \(descriptor.uuid.uuidString) value=\(value)")
  }

  func peripheral(_ peripheral: CBPeripheral, didOpen channel: CBL2CAPChannel?, error: Error?) {
    if let error {
      log(.error, "L2CAP open failed: \(error.localizedDescription)")
      return
    }
    guard let channel else {
      log(.error, "L2CAP open returned no channel")
      return
    }

    l2capInputStream = channel.inputStream
    l2capOutputStream = channel.outputStream
    dataXDecoder.reset()
    gattDataXDecoder.reset()
    airShieldSession.reset()
    pendingEnableTrustFramesByCandidateID = [:]
    airShieldAuthCandidateDescription = "No auth candidates"
    airShieldHandshakeProbeSent = false
    pendingAirShieldProbeFrame = nil
    pendingAirShieldProbeLogFields = nil
    airShieldProbeRetryCount = 0
    cancelPendingAirShieldProbeRetry()
    encryptedEndLinkSetupSent = false
    isL2CAPOpen = true
    refreshEnableTrustGateAvailability()
    canSendEncryptedEndLinkSetup = false
    canSendEncryptedGestureEnable = false
    secureLinkDescription = attemptDataXHandshake ? "Preparing RequestEncryption probe" : "L2CAP only"
    sessionRecorder.recordL2CAPOpen(psm: UInt16(channel.psm))
    channel.inputStream.delegate = self
    channel.outputStream.delegate = self
    channel.inputStream.schedule(in: .main, forMode: .default)
    channel.outputStream.schedule(in: .main, forMode: .default)
    channel.inputStream.open()
    channel.outputStream.open()
    log(.success, "L2CAP channel opened psm=\(channel.psm)")
    if attemptDataXHandshake {
      secureLinkDescription = "RequestEncryption probe pending"
    }
  }
}

extension BluetoothScanner: StreamDelegate {
  func stream(_ aStream: Stream, handle eventCode: Stream.Event) {
    switch eventCode {
    case .openCompleted:
      log(.success, "Stream opened")
      if aStream === l2capOutputStream, attemptDataXHandshake {
        sendAirShieldRequestEncryptionProbe()
      }
    case .hasBytesAvailable:
      readAvailableBytes(from: aStream)
    case .hasSpaceAvailable:
      log(.info, "Output stream has space")
      if aStream === l2capOutputStream, attemptDataXHandshake {
        sendAirShieldRequestEncryptionProbe()
      }
    case .errorOccurred:
      sessionRecorder.record("l2cap.stream_error", ["error": aStream.streamError?.localizedDescription ?? "unknown"])
      log(.error, "Stream error: \(aStream.streamError?.localizedDescription ?? "unknown")")
      closeL2CAPStreams(reason: "stream error")
    case .endEncountered:
      sessionRecorder.record("l2cap.stream_end")
      log(.warning, "Stream ended")
      closeL2CAPStreams(reason: "stream ended")
    default:
      break
    }
  }

  private func readAvailableBytes(from stream: Stream) {
    guard let input = stream as? InputStream else {
      return
    }
    var buffer = [UInt8](repeating: 0, count: 4096)
    while input.hasBytesAvailable {
      let count = input.read(&buffer, maxLength: buffer.count)
      if count > 0 {
        let data = Data(buffer.prefix(count))
        rawFrameCount += 1
        if dumpRawFrames {
          log(.success, "L2CAP rx bytes=\(count) hex=\(data.hexString)")
        } else {
          log(.success, "L2CAP rx bytes=\(count) rawHexSuppressed=true")
        }
        let plainFrames = dataXDecoder.append(data)
        if !plainFrames.isEmpty {
          airShieldEncryptedFrameDecoder.reset()
          sessionRecorder.recordL2CAPRX(byteCount: count, data: dumpRawFrames ? data : nil, decodedFrameCount: plainFrames.count)
          handleDecodedDataXFrames(plainFrames, source: "l2cap.plain")
          continue
        }

        var decryptedFrameCount = 0
        if airShieldSession.hasReceiveCandidates {
          let encryptedOuterFrames = airShieldEncryptedFrameDecoder.append(data)
          if !encryptedOuterFrames.isEmpty {
            dataXDecoder.reset()
          }
          for outerFrame in encryptedOuterFrames {
            let decryptedMatches = airShieldSession.decryptReceivedEncryptedFrameCandidates(outerFrame)
            if decryptedMatches.isEmpty {
              let missFields: [String: Any] = [
                "outer_frame_length": outerFrame.count,
                "outer_frame_fingerprint": Self.shortSHA256Fingerprint(outerFrame)
              ]
              sessionRecorder.recordAirShieldCandidateMiss(missFields)
              if !airShieldSession.hasValidatedReceiveCandidate {
                airShieldValidationDescription = "Candidate miss \(outerFrame.count)B"
              }
            }
            for match in decryptedMatches {
              canSendEncryptedEndLinkSetup = airShieldSession.preparedEndLinkSetupFrameForValidatedReceiveCandidate() != nil
              canSendEncryptedGestureEnable = encryptedEndLinkSetupSent
                && airShieldSession.preparedGestureEnableFrameForValidatedReceiveCandidate() != nil
              secureLinkDescription = "AirShield candidate decrypt matched"
              airShieldValidationDescription = "\(match.sharedMaterialSource) counter +\(match.counterSearchOffset) plaintext \(match.plaintextLength)B"
              let frames = decryptedDataXDecoder.append(match.plaintext)
              decryptedFrameCount += frames.count
              sessionRecorder.recordAirShieldCandidateMatch(Self.airShieldDecryptedFrameLogFields(match, decodedFrameCount: frames.count))
              log(.success, "AirShield decrypted candidate source=\(match.sharedMaterialSource) plaintext=\(match.plaintextLength)B dataXFrames=\(frames.count)")
              handleDecodedDataXFrames(frames, source: "airshield.decrypted")
            }
          }
        }
        sessionRecorder.recordL2CAPRX(byteCount: count, data: dumpRawFrames ? data : nil, decodedFrameCount: decryptedFrameCount)
      } else if count < 0 {
        log(.error, "L2CAP read failed: \(input.streamError?.localizedDescription ?? "unknown")")
        break
      } else {
        break
      }
    }
  }

  private func handleDecodedDataXFrames(_ frames: [DataXFrame], source: String) {
    for frame in frames {
      decodedFrameCount += 1
      sessionRecorder.recordDecodedDataXFrame(frame)
      var frameSourceFields: [String: Any] = [
        "source": source,
        "total_length": frame.totalLength,
        "payload_length": frame.payload.count,
        "payload_fingerprint": frame.payloadFingerprint,
        "channel_alias": frame.channelAlias.map(Int.init) ?? -1,
        "typed_buffer_type": frame.typedBufferType.map(Int.init) ?? -1,
        "app_id": frame.decodedAppID.map(Int.init) ?? -1,
        "message_type": frame.decodedMessageType.map(Int.init) ?? -1
      ]
      if let authServiceName = frame.airShieldAuthServiceName {
        frameSourceFields["airshield_auth_service"] = authServiceName
      }
      if let authTypedBufferName = frame.airShieldAuthTypedBufferName {
        frameSourceFields["airshield_auth_typed_buffer"] = authTypedBufferName
      }
      sessionRecorder.record("datax.frame_source", frameSourceFields)
      if let authPayload = frame.decodedAirShieldAuthPayload {
        var authPayloadFields = authPayload.logFields
        authPayloadFields["source"] = source
        sessionRecorder.record("airshield.auth_payload.rx", authPayloadFields)
      }
      log(.info, frame.description)
      if handleAirShieldLinkSetupFrame(frame) {
        continue
      }
      if frame.decodedAppID == WISProtocol.AppID.emgImu.rawValue,
         frame.decodedMessageType == WISProtocol.MessageType.gesture.rawValue,
         let gesture = GestureEventDecoder.decode(frame.payload) {
        let sourceName = connectedPeripheralID
         .flatMap { peripheralsByID[$0] }
         .map { displayName(for: $0) } ?? "unknown"
        let gestureFields = EventForwarder.sessionPayloadJSON(
          gesture: gesture,
          source: sourceName,
          frame: frame,
          frameSource: source,
          date: Date()
        )
        sessionRecorder.recordDecodedGesture(gestureFields)
        let forwardedEvent = eventForwarder.forward(gesture, source: sourceName, frame: frame)
        gestureEntries.append(forwardedEvent)
        if gestureEntries.count > 100 {
          gestureEntries.removeFirst(gestureEntries.count - 100)
        }
        log(.success, "Forwarded \(gesture.description)")
      } else if frame.decodedAppID == WISProtocol.AppID.rpc.rawValue,
                frame.decodedMessageType == WISProtocol.MessageType.response.rawValue,
                let response = StreamControlDecoder.decodeRPCResponse(frame.payload) {
        var fields = response.logFields
        fields["source"] = source
        fields["payload_length"] = frame.payload.count
        fields["app_id"] = Int(WISProtocol.AppID.rpc.rawValue)
        fields["message_type"] = Int(WISProtocol.MessageType.response.rawValue)
        sessionRecorder.recordWISStreamControlResponse(fields)
        log(.success, response.description)
        if response.streamControlResponse?.isGestureStreamActive == true {
          secureLinkDescription = "Gesture stream active"
        }
      } else if frame.decodedAppID == WISProtocol.AppID.rpc.rawValue,
                frame.decodedMessageType == WISProtocol.MessageType.streamUpdate.rawValue,
                let update = StreamControlDecoder.decodeRPCStreamUpdate(frame.payload) {
        var fields = update.logFields
        fields["source"] = source
        fields["payload_length"] = frame.payload.count
        fields["app_id"] = Int(WISProtocol.AppID.rpc.rawValue)
        fields["message_type"] = Int(WISProtocol.MessageType.streamUpdate.rawValue)
        sessionRecorder.recordWISStreamControlUpdate(fields)
        log(.success, update.description)
        if update.streamControlUpdate?.response?.isGestureStreamActive == true {
          secureLinkDescription = "Gesture stream active"
        }
      } else if frame.decodedMessageType == WISProtocol.MessageType.authentication.rawValue
                || frame.decodedMessageType == WISProtocol.MessageType.encryption.rawValue {
        let summary = ProtoMessageSummarizer.summarize(frame.payload)
        sessionRecorder.record("datax.opaque_proto_summary", [
          "source": source,
          "payload_length": summary.payloadLength,
          "channel_alias": frame.channelAlias.map(Int.init) ?? -1,
          "typed_buffer_type": frame.typedBufferType.map(Int.init) ?? -1,
          "app_id": frame.decodedAppID.map(Int.init) ?? -1,
          "message_type": frame.decodedMessageType.map(Int.init) ?? -1,
          "field_count": summary.fields.count,
          "truncated": summary.truncated,
          "fields": summary.logFields
        ])
        log(.info, summary.description)
      }
    }
  }
}

private extension BluetoothScanner {
  func refreshEnableTrustGateAvailability() {
    guard let candidateID = loadedEnableTrustGateCandidateID else {
      canSendAirShieldEnableTrust = false
      airShieldAuthGateDescription = "No auth gate loaded"
      return
    }
    guard let frame = pendingEnableTrustFramesByCandidateID[candidateID] else {
      canSendAirShieldEnableTrust = false
      airShieldAuthGateDescription = "Gate loaded, waiting for staged candidate"
      return
    }
    let frameFingerprint = Self.shortSHA256Fingerprint(frame)
    if let expected = loadedEnableTrustGateFrameFingerprint,
       expected != "nil",
       !AirShieldEnableTrustGate.fingerprintMatches(expected, frameFingerprint) {
      canSendAirShieldEnableTrust = false
      airShieldAuthGateDescription = "Gate fingerprint mismatch"
      return
    }
    canSendAirShieldEnableTrust = isL2CAPOpen
    airShieldAuthGateDescription = isL2CAPOpen
      ? "Gate ready \(candidateID)"
      : "Gate matched, waiting for L2CAP"
  }

  static func isExactTargetBand(name: String?) -> Bool {
    BandScanner.isExactTargetBand(name: name)
  }

  static func isLikelyBand(name: String?, advertisementSummary: String) -> Bool {
    BandScanner.isLikelyBand(name: name, advertisementSummary: advertisementSummary)
  }

  static func isDADADataXCharacteristic(_ characteristic: CBCharacteristic) -> Bool {
    characteristic.uuid.uuidString.uppercased() == "0000DADA-0000-0000-8000-34635C9B94FB"
  }

  static func hasTargetBandServices(_ services: [CBService]) -> Bool {
    BandScanner.hasTargetBandServices(services)
  }

  func shouldLogDiscovery(_ item: DiscoveredPeripheral) -> Bool {
    let now = Date()
    defer {
      loggedDiscoveryByID[item.id] = (date: now, rssi: item.rssi, advertisementSummary: item.advertisementSummary)
    }

    guard let previous = loggedDiscoveryByID[item.id] else {
      return true
    }

    if previous.advertisementSummary != item.advertisementSummary {
      return true
    }

    let secondsSinceLastLog = now.timeIntervalSince(previous.date)
    let rssiDelta = abs(item.rssi - previous.rssi)
    if item.isCandidate {
      return secondsSinceLastLog > 15 || rssiDelta >= 20
    }
    return secondsSinceLastLog > 30 || rssiDelta >= 12
  }

  func displayName(for peripheral: CBPeripheral) -> String {
    if let name = peripheral.name, !name.isEmpty {
      return name
    }
    return discoveryByID[peripheral.identifier]?.displayName ?? "Unnamed Peripheral"
  }

  func errorDescription(_ error: Error?) -> String {
    error?.localizedDescription ?? "no error"
  }

  func isStalePairingError(_ error: Error?) -> Bool {
    guard let error else {
      return false
    }
    let description = error.localizedDescription.lowercased()
    return description.contains("peer removed pairing information")
  }

  func loadStoredAirShieldIdentity() {
    do {
      airShieldIdentityMaterial = try AirShieldIdentityKeychain.load()
      if let material = airShieldIdentityMaterial {
        selectedIdentitySlot = material.slot
        sessionRecorder.recordAirShieldIdentityLoaded(airShieldIdentityLogFields(material))
        log(.success, "Loaded AirShield identity \(material.summary)")
      }
      updateAirShieldIdentityDescription()
    } catch {
      airShieldIdentityMaterial = nil
      updateAirShieldIdentityDescription()
      sessionRecorder.record("airshield.identity.load_failed", ["error": String(describing: error)])
      log(.error, "AirShield identity load failed: \(error)")
    }
  }

  func updateAirShieldIdentityDescription() {
    if let material = airShieldIdentityMaterial {
      airShieldIdentityDescription = material.summary
    } else {
      airShieldIdentityDescription = "No identity imported"
    }
  }

  func airShieldIdentityLogFields(_ material: AirShieldIdentityMaterial) -> [String: Any] {
    [
      "slot": material.slot.rawValue,
      "raw_private_key_length": material.rawPrivateKey.count,
      "private_key_fingerprint": material.privateKeyFingerprint,
      "raw_public_key_length": material.rawPublicKey?.count ?? 0,
      "public_key_fingerprint": material.publicKeyFingerprint ?? "nil",
      "accepted_auth_public_key_length": material.acceptedAuthenticationPublicKey?.count ?? 0,
      "accepted_auth_public_key_fingerprint": material.acceptedAuthenticationPublicKeyFingerprint ?? "nil",
      "public_key_candidates": material.publicKeyCandidates.map { candidate in
        [
          "source": candidate.source,
          "raw_public_key_length": candidate.rawPublicKey.count,
          "public_key_fingerprint": candidate.publicKeyFingerprint,
          "accepted_auth_public_key_length": candidate.acceptedAuthenticationPublicKey.count,
          "accepted_auth_public_key_fingerprint": candidate.acceptedAuthenticationPublicKeyFingerprint
        ]
      },
      "parse_status": material.parseStatus
    ]
  }

  func openDetectedL2CAPPSM(_ psm: UInt16, source: String) {
    guard autoOpenDetectedL2CAP else {
      log(.info, "Detected LE L2CAP PSM \(psm) from \(source); auto-open disabled")
      return
    }
    guard L2CAPSession.isDynamicLEPSM(psm) else {
      return
    }
    guard !openedL2CAPPSMs.contains(psm) else {
      return
    }
    guard let connectedPeripheralID, let peripheral = peripheralsByID[connectedPeripheralID] else {
      return
    }

    openedL2CAPPSMs.insert(psm)
    log(.success, "Detected LE L2CAP PSM \(psm) from \(source); opening channel")
    peripheral.openL2CAPChannel(CBL2CAPPSM(psm))
  }

  func scheduleReconnectIfNeeded(for peripheral: CBPeripheral, reason: String, error: Error?) {
    guard autoConnectExactBand else {
      reconnectDescription = "Auto-reconnect disabled"
      return
    }
    guard !manualDisconnectRequested else {
      reconnectDescription = "Stopped by user"
      sessionRecorder.recordReconnectSkipped([
        "reason": reason,
        "skip_reason": "manual_disconnect",
        "peripheral_id": peripheral.identifier.uuidString,
        "name": displayName(for: peripheral)
      ])
      return
    }
    guard isExactKnownBand(peripheral) else {
      reconnectDescription = "Idle"
      return
    }
    if isStalePairingError(error) {
      cancelPendingReconnect()
      reconnectDescription = "Stale pairing"
      connectionDescription = "Pairing needs reset"
      sessionRecorder.recordReconnectSkipped([
        "reason": reason,
        "skip_reason": "stale_pairing",
        "peripheral_id": peripheral.identifier.uuidString,
        "name": displayName(for: peripheral),
        "error": errorDescription(error),
        "next_action": "Forget the band in macOS Bluetooth settings, put the band back in pairing mode, then scan again."
      ])
      log(.error, "Stale pairing for \(displayName(for: peripheral)); forget the device in macOS Bluetooth settings and pair again")
      return
    }
    guard reconnectAttemptCount < maximumReconnectAttempts else {
      reconnectDescription = "Reconnect limit reached"
      sessionRecorder.record("ble.reconnect_exhausted", [
        "reason": reason,
        "peripheral_id": peripheral.identifier.uuidString,
        "name": displayName(for: peripheral),
        "attempts": reconnectAttemptCount
      ])
      log(.error, "Auto-reconnect limit reached for \(displayName(for: peripheral))")
      return
    }

    cancelPendingReconnect()
    reconnectAttemptCount += 1
    let delay = min(30.0, pow(2.0, Double(reconnectAttemptCount - 1)))
    reconnectDescription = "Retry \(reconnectAttemptCount)/\(maximumReconnectAttempts) in \(Int(delay))s"
    sessionRecorder.record("ble.reconnect_scheduled", [
      "reason": reason,
      "peripheral_id": peripheral.identifier.uuidString,
      "name": displayName(for: peripheral),
      "attempt": reconnectAttemptCount,
      "delay_seconds": delay,
      "error": errorDescription(error)
    ])
    log(.warning, "Auto-reconnect \(reconnectAttemptCount)/\(maximumReconnectAttempts) scheduled in \(Int(delay))s for \(displayName(for: peripheral))")

    let workItem = DispatchWorkItem { [weak self, weak peripheral] in
      guard let self, let peripheral else {
        return
      }
      guard self.autoConnectExactBand, !self.manualDisconnectRequested else {
        self.reconnectDescription = self.manualDisconnectRequested ? "Stopped by user" : "Auto-reconnect disabled"
        return
      }

      self.peripheralsByID[peripheral.identifier] = peripheral
      self.selectedPeripheralID = peripheral.identifier
      self.connectionDescription = "Reconnecting to \(self.displayName(for: peripheral))"
      self.reconnectDescription = "Retry \(self.reconnectAttemptCount)/\(self.maximumReconnectAttempts) connecting"
      self.sessionRecorder.recordConnection(
        "ble.reconnect_attempt",
        peripheral: peripheral,
        name: self.displayName(for: peripheral)
      )
      self.log(.info, "Auto-reconnecting to \(self.displayName(for: peripheral))")
      self.central.connect(peripheral, options: nil)
      self.scheduleConnectTimeout(for: peripheral, reason: "reconnect_attempt")
    }
    pendingReconnectWorkItem = workItem
    DispatchQueue.main.asyncAfter(deadline: .now() + delay, execute: workItem)
  }

  func scheduleConnectTimeout(for peripheral: CBPeripheral, reason: String) {
    cancelPendingConnectTimeout()
    let timeoutSeconds = 20.0
    let workItem = DispatchWorkItem { [weak self, weak peripheral] in
      guard let self, let peripheral else {
        return
      }
      guard self.connectedPeripheralID != peripheral.identifier else {
        return
      }
      self.consecutiveConnectTimeoutCount += 1
      self.connectionDescription = "Connect timed out"
      self.sessionRecorder.recordConnectTimeout(
        peripheralID: peripheral.identifier,
        name: self.displayName(for: peripheral),
        reason: reason,
        timeoutSeconds: timeoutSeconds,
        consecutiveTimeouts: self.consecutiveConnectTimeoutCount
      )
      self.log(.warning, "Connect timeout \(self.consecutiveConnectTimeoutCount)/\(self.maximumConsecutiveConnectTimeouts) for \(self.displayName(for: peripheral)); cancelling attempt")
      self.central.cancelPeripheralConnection(peripheral)
      self.timeoutScheduledReconnectPeripheralIDs.insert(peripheral.identifier)
      guard self.consecutiveConnectTimeoutCount < self.maximumConsecutiveConnectTimeouts else {
        self.cancelPendingReconnect()
        self.connectionDescription = "Pairing reset recommended"
        self.reconnectDescription = "Connect timeouts"
        self.sessionRecorder.recordReconnectSkipped([
          "reason": reason,
          "skip_reason": "repeated_connect_timeouts",
          "peripheral_id": peripheral.identifier.uuidString,
          "name": self.displayName(for: peripheral),
          "consecutive_timeouts": self.consecutiveConnectTimeoutCount,
          "next_action": "Forget or reset the band pairing in macOS Bluetooth settings, put the band back in pairing mode, then scan again."
        ])
        self.log(.error, "Repeated connect timeouts for \(self.displayName(for: peripheral)); reset macOS pairing and scan again")
        return
      }
      self.scheduleReconnectIfNeeded(for: peripheral, reason: "connect_timeout", error: nil)
    }
    pendingConnectTimeoutWorkItem = workItem
    DispatchQueue.main.asyncAfter(deadline: .now() + timeoutSeconds, execute: workItem)
  }

  func scheduleLikelyAutoConnect() {
    guard pendingLikelyAutoConnectWorkItem == nil else {
      return
    }
    let delay = 2.0
    sessionRecorder.record("ble.likely_auto_connect_scheduled", [
      "delay_seconds": delay
    ])
    log(.info, "Likely pairing-mode band seen; choosing strongest candidate in \(Int(delay))s")
    let workItem = DispatchWorkItem { [weak self] in
      guard let self else {
        return
      }
      self.pendingLikelyAutoConnectWorkItem = nil
      guard self.autoConnectLikelyPairingBand,
            self.connectedPeripheralID == nil,
            !self.hasAutoConnectedToExactBand,
            !self.hasAutoConnectedToLikelyBand else {
        return
      }
      self.hasAutoConnectedToLikelyBand = true
      self.connectStrongestLikelyBand()
    }
    pendingLikelyAutoConnectWorkItem = workItem
    DispatchQueue.main.asyncAfter(deadline: .now() + delay, execute: workItem)
  }

  func cancelPendingReconnect() {
    pendingReconnectWorkItem?.cancel()
    pendingReconnectWorkItem = nil
  }

  func cancelPendingConnectTimeout() {
    pendingConnectTimeoutWorkItem?.cancel()
    pendingConnectTimeoutWorkItem = nil
  }

  func cancelPendingLikelyAutoConnect() {
    pendingLikelyAutoConnectWorkItem?.cancel()
    pendingLikelyAutoConnectWorkItem = nil
  }

  func isExactKnownBand(_ peripheral: CBPeripheral) -> Bool {
    if Self.isExactTargetBand(name: peripheral.name) {
      return true
    }
    return discoveryByID[peripheral.identifier]?.isExactBand == true
  }

  func closeL2CAPStreams(reason: String) {
    let hadStreams = l2capInputStream != nil || l2capOutputStream != nil
    if let input = l2capInputStream {
      input.delegate = nil
      input.remove(from: .main, forMode: .default)
      input.close()
    }
    if let output = l2capOutputStream {
      output.delegate = nil
      output.remove(from: .main, forMode: .default)
      output.close()
    }
    l2capInputStream = nil
    l2capOutputStream = nil
    isL2CAPOpen = false
    openedL2CAPPSMs.removeAll()
    dataXDecoder.reset()
    gattDataXDecoder.reset()
    airShieldEncryptedFrameDecoder.reset()
    decryptedDataXDecoder.reset()
    airShieldSession.reset()
    pendingEnableTrustFramesByCandidateID = [:]
    airShieldAuthCandidateDescription = "No auth candidates"
    airShieldHandshakeProbeSent = false
    pendingAirShieldProbeFrame = nil
    pendingAirShieldProbeLogFields = nil
    airShieldProbeRetryCount = 0
    cancelPendingAirShieldProbeRetry()
    encryptedEndLinkSetupSent = false
    canSendAirShieldEnableTrust = false
    canSendEncryptedEndLinkSetup = false
    canSendEncryptedGestureEnable = false
    refreshEnableTrustGateAvailability()
    airShieldValidationDescription = "No validation yet"
    secureLinkDescription = connectedPeripheralID == nil ? "Not started" : "L2CAP closed"
    if hadStreams {
      sessionRecorder.record("l2cap.closed", ["reason": reason])
      log(.warning, "L2CAP streams closed: \(reason)")
    }
  }

  func sendAirShieldRequestEncryptionProbe() {
    guard !airShieldHandshakeProbeSent else {
      return
    }
    do {
      let prepared = try prepareAirShieldRequestEncryptionProbeIfNeeded()
      secureLinkDescription = "RequestEncryption probe ready"
      if sendL2CAPData(prepared.frame, label: "airshield.request_encryption.probe") {
        airShieldHandshakeProbeSent = true
        airShieldProbeRetryCount = 0
        cancelPendingAirShieldProbeRetry()
        pendingAirShieldProbeFrame = nil
        pendingAirShieldProbeLogFields = nil
        secureLinkDescription = "RequestEncryption probe sent"
      } else {
        secureLinkDescription = "RequestEncryption probe waiting for stream space"
        scheduleAirShieldProbeRetry(reason: "tx_not_ready")
      }
    } catch {
      secureLinkDescription = "Handshake probe failed"
      sessionRecorder.record("airshield.probe_encode_failed", ["error": String(describing: error)])
      log(.error, "Could not encode AirShield RequestEncryption probe: \(error)")
    }
  }

  func prepareAirShieldRequestEncryptionProbeIfNeeded() throws -> (frame: Data, fields: [String: Any]) {
    if let frame = pendingAirShieldProbeFrame, let fields = pendingAirShieldProbeLogFields {
      return (frame, fields)
    }
    guard let challenge = randomBytes(count: 16) else {
      secureLinkDescription = "Handshake probe failed"
      log(.error, "Could not create AirShield RequestEncryption challenge")
      throw AirShieldProbeError.randomChallengeUnavailable
    }
    let probe = try airShieldSession.makeRequestEncryptionProbe(challenge: challenge)
    let payload = AirShieldLinkSetup.encodeRequestEncryption(publicKey: probe.publicKey, challenge: probe.challenge)
    let frame = try AirShieldLinkSetup.encodeDataXFrame(
      typedMessage: .requestEncryption,
      payload: payload
    )
    var probeFields: [String: Any] = [
      "public_key_length": probe.publicKey.count,
      "challenge_length": probe.challenge.count
    ]
    if let material = airShieldIdentityMaterial {
      probeFields["identity_loaded"] = true
      probeFields["identity"] = airShieldIdentityLogFields(material)
      recordEnableTrustCandidateSummaries(material: material, requestChallenge: probe.challenge)
    } else {
      probeFields["identity_loaded"] = false
    }
    pendingAirShieldProbeFrame = frame
    pendingAirShieldProbeLogFields = probeFields
    sessionRecorder.recordAirShieldProbeStateReady(probeFields)
    return (frame, probeFields)
  }

  func scheduleAirShieldProbeRetry(reason: String) {
    guard attemptDataXHandshake, !airShieldHandshakeProbeSent else {
      return
    }
    guard pendingAirShieldProbeRetryWorkItem == nil else {
      return
    }
    guard airShieldProbeRetryCount < maximumAirShieldProbeRetries else {
      sessionRecorder.record("airshield.probe_retry_exhausted", [
        "reason": reason,
        "retry_count": airShieldProbeRetryCount
      ])
      log(.warning, "AirShield RequestEncryption probe retry exhausted")
      sendPendingAirShieldProbeOverGATTFallback(reason: reason)
      return
    }
    airShieldProbeRetryCount += 1
    let workItem = DispatchWorkItem { [weak self] in
      guard let self else { return }
      self.pendingAirShieldProbeRetryWorkItem = nil
      self.sendAirShieldRequestEncryptionProbe()
    }
    pendingAirShieldProbeRetryWorkItem = workItem
    sessionRecorder.record("airshield.probe_retry_scheduled", [
      "reason": reason,
      "retry_count": airShieldProbeRetryCount
    ])
    DispatchQueue.main.asyncAfter(deadline: .now() + 0.25, execute: workItem)
  }

  func cancelPendingAirShieldProbeRetry() {
    pendingAirShieldProbeRetryWorkItem?.cancel()
    pendingAirShieldProbeRetryWorkItem = nil
  }

  func sendPendingAirShieldProbeOverGATTFallback(reason: String) {
    guard !airShieldHandshakeProbeSent else {
      return
    }
    guard let frame = pendingAirShieldProbeFrame else {
      sessionRecorder.record("airshield.probe_gatt_fallback_blocked", [
        "reason": "no_pending_probe_frame",
        "trigger": reason
      ])
      return
    }
    if sendGATTDataXData(frame, label: "airshield.request_encryption.probe.gatt_fallback") {
      airShieldHandshakeProbeSent = true
      pendingAirShieldProbeFrame = nil
      pendingAirShieldProbeLogFields = nil
      secureLinkDescription = "RequestEncryption probe sent over GATT fallback"
      sessionRecorder.record("airshield.probe_gatt_fallback_sent", [
        "trigger": reason,
        "frame_length": frame.count,
        "frame_fingerprint": Self.shortSHA256Fingerprint(frame)
      ])
      log(.success, "AirShield RequestEncryption probe sent over GATT DataX fallback")
    }
  }

  func recordEnableTrustCandidateSummaries(
    material: AirShieldIdentityMaterial,
    requestChallenge: Data
  ) {
    let challengeSources: [(source: String, challengeHash: Data)] = [
      ("raw_preamble_tx_challenge_non_native_probe", requestChallenge),
      ("sha256_preamble_tx_challenge_non_native_probe", Data(SHA256.hash(data: requestChallenge)))
    ]

    var candidates: [[String: Any]] = []
    var stagedFrameCount = 0
    for challengeSource in challengeSources {
      let summaries = material.enableTrustCandidateSummaries(challengeHash: challengeSource.challengeHash)
      for summary in summaries {
        var fields = summary.logFields
        fields["challenge_hash_source"] = challengeSource.source
        candidates.append(fields)
        if let frame = summary.frame {
          pendingEnableTrustFramesByCandidateID[summary.candidateID] = frame
          stagedFrameCount += 1
        }
      }
    }

    guard !candidates.isEmpty else {
      airShieldAuthCandidateDescription = "No auth candidates"
      sessionRecorder.recordAirShieldEnableTrustCandidatesUnavailable([
        "slot": material.slot.rawValue,
        "private_key_fingerprint": material.privateKeyFingerprint,
        "reason": "no_parseable_p256_scalar_or_empty_challenge"
      ])
      return
    }

    airShieldAuthCandidateDescription = "\(stagedFrameCount) auth candidate frames staged"
    refreshEnableTrustGateAvailability()
    sessionRecorder.recordAirShieldEnableTrustCandidatesPrepared([
      "slot": material.slot.rawValue,
      "private_key_fingerprint": material.privateKeyFingerprint,
      "candidate_count": candidates.count,
      "staged_frame_count": stagedFrameCount,
      "candidates": candidates
    ])
  }

  func sendEncryptedGestureEnableIfValidated() {
    guard encryptedEndLinkSetupSent else {
      sessionRecorder.record("airshield.gesture_enable.tx_blocked", [
        "reason": "end_link_setup_not_sent"
      ])
      log(.warning, "Encrypted gesture enable blocked until EndLinkSetup is sent")
      return
    }
    guard canSendEncryptedGestureEnable,
          let prepared = airShieldSession.preparedGestureEnableFrameForValidatedReceiveCandidate() else {
      sessionRecorder.record("airshield.gesture_enable.tx_blocked", [
        "reason": "no_validated_receive_candidate"
      ])
      log(.warning, "Encrypted gesture enable blocked until AirShield candidate decrypt validates")
      return
    }

    let readyFields: [String: Any] = [
      "shared_material_source": prepared.sharedMaterialSource
    ].merging(Self.airShieldFrameCandidateLogFields(prepared.summary)) { current, _ in current }
    sessionRecorder.recordAirShieldGestureEnableReady(readyFields)
    if sendL2CAPData(prepared.outerFrame, label: "airshield.gesture_enable.encrypted_candidate") {
      sessionRecorder.recordAirShieldGestureEnableSent(readyFields)
      secureLinkDescription = "Gesture enable candidate sent"
      airShieldValidationDescription = "Gesture enable sent via \(prepared.sharedMaterialSource)"
    }
  }

  func sendEncryptedEndLinkSetupIfValidated() {
    guard canSendEncryptedEndLinkSetup,
          let prepared = airShieldSession.preparedEndLinkSetupFrameForValidatedReceiveCandidate() else {
      sessionRecorder.record("airshield.end_link_setup.tx_blocked", [
        "reason": "no_validated_receive_candidate"
      ])
      log(.warning, "Encrypted EndLinkSetup blocked until AirShield candidate decrypt validates")
      return
    }

    let fields: [String: Any] = [
      "shared_material_source": prepared.sharedMaterialSource,
      "local_uuid": airShieldSession.localEndLinkSetupUUID?.uuidString ?? "nil"
    ].merging(Self.airShieldFrameCandidateLogFields(prepared.summary)) { current, _ in current }
    sessionRecorder.recordAirShieldEndLinkSetupReady(fields)
    if sendL2CAPData(prepared.outerFrame, label: "airshield.end_link_setup.encrypted_candidate") {
      sessionRecorder.recordAirShieldEndLinkSetupSent(fields)
      encryptedEndLinkSetupSent = true
      canSendEncryptedEndLinkSetup = false
      canSendEncryptedGestureEnable = airShieldSession.preparedGestureEnableFrameForValidatedReceiveCandidate() != nil
      secureLinkDescription = "EndLinkSetup candidate sent"
      airShieldValidationDescription = "EndLinkSetup sent via \(prepared.sharedMaterialSource)"
    }
  }

  func handleAirShieldLinkSetupFrame(_ frame: DataXFrame) -> Bool {
    guard frame.channelAlias == AirShieldLinkSetup.dataXServiceID else {
      return false
    }
    guard let typedMessage = frame.airShieldTypedMessage,
          let decoded = frame.decodedAirShieldMessage else {
      sessionRecorder.record("airshield.link_setup.rx_unknown", [
        "typed_buffer_type": Int(frame.typedBufferType ?? 0),
        "payload_length": frame.payload.count
      ])
      log(.warning, "AirShield link-setup unknown typedBufferType=\(frame.typedBufferType.map(String.init) ?? "nil") payload=\(frame.payload.count)B")
      return true
    }

    var fields: [String: Any] = [
      "typed_message": String(describing: typedMessage),
      "typed_buffer_type": Int(typedMessage.rawValue),
      "payload_length": frame.payload.count,
      "summary": decoded.description
    ]

    switch decoded {
    case .requestEncryption(let message):
      fields["public_key_length"] = message.publicKey?.count ?? 0
      fields["challenge_length"] = message.challenge?.count ?? 0
      fields["uses_hkdf"] = message.usesHKDF
      if let publicKey = message.publicKey {
        fields["public_key_fingerprint"] = Self.shortSHA256Fingerprint(publicKey)
      }
      if let challenge = message.challenge {
        fields["challenge_fingerprint"] = Self.shortSHA256Fingerprint(challenge)
      }
      if let ellipticCurve = message.ellipticCurve {
        fields["elliptic_curve"] = Int(ellipticCurve)
      }
      if let supportedParameters = message.supportedParameters {
        fields["supported_parameters"] = String(supportedParameters)
      }
      fields["key_hint_count"] = message.keyHints.count
      if !message.keyHints.isEmpty {
        fields["key_hints"] = message.keyHints.map(Self.airShieldKeyHintLogFields)
      }
      if let quirks = message.quirks {
        fields["quirks"] = Int(quirks)
      }
      if let airShieldVersion = message.airShieldVersion {
        fields["airshield_version"] = Int(airShieldVersion)
      }
    case .enableEncryption(let message):
      fields["public_key_length"] = message.publicKey?.count ?? 0
      fields["seed_length"] = message.seed?.count ?? 0
      fields["iv_length"] = message.initializationVector?.count ?? 0
      fields["uses_hkdf"] = message.usesHKDF
      if let publicKey = message.publicKey {
        fields["public_key_fingerprint"] = Self.shortSHA256Fingerprint(publicKey)
      }
      if let seed = message.seed {
        fields["seed_fingerprint"] = Self.shortSHA256Fingerprint(seed)
      }
      if let initializationVector = message.initializationVector {
        fields["iv_fingerprint"] = Self.shortSHA256Fingerprint(initializationVector)
      }
      if let base = message.base {
        fields["base"] = String(base)
      }
      if let parameters = message.parameters {
        fields["parameters"] = String(parameters)
      }
      if let quirks = message.quirks {
        fields["quirks"] = Int(quirks)
      }
      if let phasedLinkSetupSupported = message.phasedLinkSetupSupported {
        fields["phased_link_setup_supported"] = phasedLinkSetupSupported
      }
      if let supportedLinkSetupServices = message.supportedLinkSetupServices {
        fields["supported_link_setup_services"] = String(supportedLinkSetupServices)
      }
      if let linkSwitchVersionSupported = message.linkSwitchVersionSupported {
        fields["link_switch_version_supported"] = String(linkSwitchVersionSupported)
      }
      do {
        let inputs = try airShieldSession.processEnableEncryption(message)
        fields["shared_secret_length"] = inputs.sharedSecretLength
        fields["shared_secret_fingerprint"] = inputs.sharedSecretFingerprint
        fields["local_challenge_length"] = inputs.localChallengeLength
        fields["local_challenge_fingerprint"] = inputs.localChallengeFingerprint
        fields["peer_public_key_fingerprint"] = inputs.peerPublicKeyFingerprint
        if let seedFingerprint = inputs.seedFingerprint {
          fields["seed_fingerprint"] = seedFingerprint
        }
        if let ivFingerprint = inputs.initializationVectorFingerprint {
          fields["iv_fingerprint"] = ivFingerprint
        }
        let materialCandidateFields = inputs.normalMaterialCandidates.map(Self.airShieldMaterialCandidateLogFields)
        if !materialCandidateFields.isEmpty {
          fields["normal_material_candidates"] = materialCandidateFields
        }
        if let material = inputs.normalMaterialCandidate {
          fields["normal_material_shared_source"] = material.sharedMaterialSource
          fields["normal_material_shared_prefix_hex"] = material.sharedMaterialPrefixHex
          fields["normal_material_shared_fingerprint"] = material.sharedMaterialFingerprint
          fields["normal_material_shared_sha256_fingerprint"] = material.sharedMaterialSHA256Fingerprint
          fields["normal_material_transcript_challenge_window_fingerprint"] = material.transcriptChallengeWindowFingerprint
          fields["normal_material_transcript_material_window_fingerprint"] = material.transcriptMaterialWindowFingerprint
          fields["normal_material_transcript_digest_input_fingerprint"] = material.transcriptDigestInputFingerprint
          fields["normal_material_key_derivation_mode"] = material.keyDerivationMode
          if let source = material.expansionContextSource {
            fields["normal_material_expansion_context_source"] = source
          }
          if let length = material.expansionContextLength {
            fields["normal_material_expansion_context_length"] = length
          }
          if let fingerprint = material.expansionContextFingerprint {
            fields["normal_material_expansion_context_fingerprint"] = fingerprint
          }
          fields["normal_material_transcript_digest_fingerprint"] = material.transcriptDigestFingerprint
          fields["normal_material_work_area_fingerprint"] = material.workAreaFingerprint
          fields["normal_material_work_area_validation_half_fingerprint"] = material.workAreaValidationHalfFingerprint
          fields["normal_material_work_area_cipher_half_fingerprint"] = material.workAreaCipherHalfFingerprint
          fields["normal_material_validation_key_fingerprint"] = material.validationKeyFingerprint
          fields["normal_material_cipher_key_fingerprint"] = material.cipherKeyFingerprint
          fields["normal_material_validation_equals_cipher"] = material.validationEqualsCipher
          fields["normal_material_validation_key_source"] = material.validationKeySource
          fields["normal_material_cipher_key_source"] = material.cipherKeySource
          fields["normal_material_transcript_prefix_source"] = material.transcriptPrefixSource
          if let counterSource = material.initialCounterBlockSource {
            fields["normal_material_initial_counter_block_source"] = counterSource
          }
          if let counterFingerprint = material.initialCounterBlockFingerprint {
            fields["normal_material_initial_counter_block_fingerprint"] = counterFingerprint
          }
          if let frameCandidate = material.gestureEnableFrameCandidate {
            fields["normal_material_gesture_enable_frame_candidate"] = Self.airShieldFrameCandidateLogFields(frameCandidate)
          }
          if let frameCandidate = material.endLinkSetupFrameCandidate {
            fields["normal_material_end_link_setup_frame_candidate"] = Self.airShieldFrameCandidateLogFields(frameCandidate)
          }
        }
        var readyFields: [String: Any] = [
          "peer_public_key_length": inputs.peerPublicKeyLength,
          "seed_length": inputs.seedLength,
          "iv_length": inputs.initializationVectorLength,
          "base": inputs.base.map(String.init) ?? "nil",
          "uses_hkdf": inputs.usesHKDF,
          "shared_secret_length": inputs.sharedSecretLength,
          "shared_secret_fingerprint": inputs.sharedSecretFingerprint,
          "local_challenge_length": inputs.localChallengeLength,
          "local_challenge_fingerprint": inputs.localChallengeFingerprint,
          "peer_public_key_fingerprint": inputs.peerPublicKeyFingerprint
        ]
        if let parameters = message.parameters {
          readyFields["parameters"] = String(parameters)
        }
        if let quirks = message.quirks {
          readyFields["quirks"] = Int(quirks)
        }
        if let phasedLinkSetupSupported = message.phasedLinkSetupSupported {
          readyFields["phased_link_setup_supported"] = phasedLinkSetupSupported
        }
        if let supportedLinkSetupServices = message.supportedLinkSetupServices {
          readyFields["supported_link_setup_services"] = String(supportedLinkSetupServices)
        }
        if let linkSwitchVersionSupported = message.linkSwitchVersionSupported {
          readyFields["link_switch_version_supported"] = String(linkSwitchVersionSupported)
        }
        if let seedFingerprint = inputs.seedFingerprint {
          readyFields["seed_fingerprint"] = seedFingerprint
        }
        if let ivFingerprint = inputs.initializationVectorFingerprint {
          readyFields["iv_fingerprint"] = ivFingerprint
        }
        if !materialCandidateFields.isEmpty {
          readyFields["normal_material_candidates"] = materialCandidateFields
        }
        if let material = inputs.normalMaterialCandidate {
          readyFields["normal_material_shared_source"] = material.sharedMaterialSource
          readyFields["normal_material_shared_prefix_hex"] = material.sharedMaterialPrefixHex
          readyFields["normal_material_shared_fingerprint"] = material.sharedMaterialFingerprint
          readyFields["normal_material_shared_sha256_fingerprint"] = material.sharedMaterialSHA256Fingerprint
          readyFields["normal_material_transcript_challenge_window_fingerprint"] = material.transcriptChallengeWindowFingerprint
          readyFields["normal_material_transcript_material_window_fingerprint"] = material.transcriptMaterialWindowFingerprint
          readyFields["normal_material_transcript_digest_input_fingerprint"] = material.transcriptDigestInputFingerprint
          readyFields["normal_material_key_derivation_mode"] = material.keyDerivationMode
          if let source = material.expansionContextSource {
            readyFields["normal_material_expansion_context_source"] = source
          }
          if let length = material.expansionContextLength {
            readyFields["normal_material_expansion_context_length"] = length
          }
          if let fingerprint = material.expansionContextFingerprint {
            readyFields["normal_material_expansion_context_fingerprint"] = fingerprint
          }
          readyFields["normal_material_transcript_digest_fingerprint"] = material.transcriptDigestFingerprint
          readyFields["normal_material_work_area_fingerprint"] = material.workAreaFingerprint
          readyFields["normal_material_work_area_validation_half_fingerprint"] = material.workAreaValidationHalfFingerprint
          readyFields["normal_material_work_area_cipher_half_fingerprint"] = material.workAreaCipherHalfFingerprint
          readyFields["normal_material_validation_key_fingerprint"] = material.validationKeyFingerprint
          readyFields["normal_material_cipher_key_fingerprint"] = material.cipherKeyFingerprint
          readyFields["normal_material_validation_equals_cipher"] = material.validationEqualsCipher
          readyFields["normal_material_validation_key_source"] = material.validationKeySource
          readyFields["normal_material_cipher_key_source"] = material.cipherKeySource
          readyFields["normal_material_transcript_prefix_source"] = material.transcriptPrefixSource
          if let counterSource = material.initialCounterBlockSource {
            readyFields["normal_material_initial_counter_block_source"] = counterSource
          }
          if let counterFingerprint = material.initialCounterBlockFingerprint {
            readyFields["normal_material_initial_counter_block_fingerprint"] = counterFingerprint
          }
          if let frameCandidate = material.gestureEnableFrameCandidate {
            readyFields["normal_material_gesture_enable_frame_candidate"] = Self.airShieldFrameCandidateLogFields(frameCandidate)
          }
          if let frameCandidate = material.endLinkSetupFrameCandidate {
            readyFields["normal_material_end_link_setup_frame_candidate"] = Self.airShieldFrameCandidateLogFields(frameCandidate)
          }
        }
        sessionRecorder.recordAirShieldEnableInputsReady(readyFields)
        secureLinkDescription = "EnableEncryption inputs ready"
      } catch {
        fields["derivation_error"] = String(describing: error)
        secureLinkDescription = "EnableEncryption derivation failed"
        log(.error, "AirShield EnableEncryption derivation failed: \(error)")
      }
    case .endLinkSetup(let message):
      fields["state"] = message.state.map(Int.init) ?? -1
      fields["uuid_length"] = message.uuid?.count ?? 0
      fields["link_uuid_length"] = message.linkUUID?.count ?? 0
      fields["user_data_field_count"] = message.userDataFieldCount
      secureLinkDescription = "EndLinkSetup received"
    case .knownButUndecoded:
      break
    }

    sessionRecorder.record("airshield.link_setup.rx", fields)
    log(.success, decoded.description)
    return true
  }

  private static func airShieldKeyHintLogFields(_ hint: Data) -> [String: Any] {
    [
      "length": hint.count,
      "fingerprint": Self.shortSHA256Fingerprint(hint)
    ]
  }

  private static func airShieldMaterialCandidateLogFields(_ material: AirShieldNormalFramingMaterial) -> [String: Any] {
    [
      "shared_material_source": material.sharedMaterialSource,
      "shared_material_prefix_hex": material.sharedMaterialPrefixHex,
      "shared_material_fingerprint": material.sharedMaterialFingerprint,
      "shared_material_sha256_fingerprint": material.sharedMaterialSHA256Fingerprint,
      "transcript_challenge_window_fingerprint": material.transcriptChallengeWindowFingerprint,
      "transcript_material_window_fingerprint": material.transcriptMaterialWindowFingerprint,
      "transcript_digest_input_fingerprint": material.transcriptDigestInputFingerprint,
      "key_derivation_mode": material.keyDerivationMode,
      "expansion_context_source": material.expansionContextSource ?? "nil",
      "expansion_context_length": material.expansionContextLength ?? -1,
      "expansion_context_fingerprint": material.expansionContextFingerprint ?? "nil",
      "transcript_digest_fingerprint": material.transcriptDigestFingerprint,
      "work_area_fingerprint": material.workAreaFingerprint,
      "work_area_validation_half_fingerprint": material.workAreaValidationHalfFingerprint,
      "work_area_cipher_half_fingerprint": material.workAreaCipherHalfFingerprint,
      "validation_key_fingerprint": material.validationKeyFingerprint,
      "cipher_key_fingerprint": material.cipherKeyFingerprint,
      "validation_equals_cipher": material.validationEqualsCipher,
      "validation_key_source": material.validationKeySource,
      "cipher_key_source": material.cipherKeySource,
      "transcript_prefix_source": material.transcriptPrefixSource,
      "initial_counter_block_source": material.initialCounterBlockSource ?? "nil",
      "initial_counter_block_fingerprint": material.initialCounterBlockFingerprint ?? "nil",
      "end_link_setup_frame_candidate": material.endLinkSetupFrameCandidate.map(Self.airShieldFrameCandidateLogFields) ?? [:],
      "gesture_enable_frame_candidate": material.gestureEnableFrameCandidate.map(Self.airShieldFrameCandidateLogFields) ?? [:]
    ]
  }

  private static func airShieldFrameCandidateLogFields(_ summary: AirShieldFrameCandidateSummary) -> [String: Any] {
    [
      "plaintext_source": summary.plaintextSource,
      "plaintext_length": summary.plaintextLength,
      "padded_plaintext_length": summary.paddedPlaintextLength,
      "cipher_payload_length": summary.cipherPayloadLength,
      "outer_frame_length": summary.outerFrameLength,
      "runtime_validation_mode": Int(summary.runtimeValidationMode),
      "frame_counter": String(summary.frameCounter),
      "validation_prefix_hex": summary.validationPrefixHex,
      "plaintext_fingerprint": summary.plaintextFingerprint,
      "cipher_payload_fingerprint": summary.cipherPayloadFingerprint,
      "outer_frame_fingerprint": summary.outerFrameFingerprint
    ]
  }

  private static func airShieldDecryptedFrameLogFields(
    _ match: AirShieldDecryptedFrameCandidate,
    decodedFrameCount: Int
  ) -> [String: Any] {
    [
      "shared_material_source": match.sharedMaterialSource,
      "plaintext_length": match.plaintextLength,
      "padded_plaintext_length": match.paddedPlaintextLength,
      "cipher_payload_length": match.cipherPayloadLength,
      "outer_frame_length": match.outerFrameLength,
      "padding_length": match.paddingLength,
      "runtime_validation_mode": Int(match.runtimeValidationMode),
      "frame_counter": String(match.frameCounter),
      "counter_search_offset": match.counterSearchOffset,
      "validation_prefix_hex": match.validationPrefixHex,
      "plaintext_fingerprint": match.plaintextFingerprint,
      "cipher_payload_fingerprint": match.cipherPayloadFingerprint,
      "decoded_frame_count": decodedFrameCount
    ]
  }

  private static func shortSHA256Fingerprint(_ data: Data) -> String {
    Data(SHA256.hash(data: data)).prefix(8).hexString
  }

  func randomBytes(count: Int) -> Data? {
    guard count > 0 else {
      return Data()
    }
    var bytes = [UInt8](repeating: 0, count: count)
    let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
    guard status == errSecSuccess else {
      return nil
    }
    return Data(bytes)
  }

  @discardableResult
  func sendGATTDataXData(_ data: Data, label: String) -> Bool {
    guard let peripheral = gattDataXWritePeripheral,
          let characteristic = gattDataXWriteCharacteristic else {
      sessionRecorder.record("gatt.datax.tx_failed", [
        "label": label,
        "reason": "no_write_characteristic"
      ])
      log(.warning, "GATT DataX tx failed for \(label): no DADA write characteristic")
      return false
    }
    guard characteristic.properties.contains(.writeWithoutResponse) || characteristic.properties.contains(.write) else {
      sessionRecorder.record("gatt.datax.tx_failed", [
        "label": label,
        "reason": "characteristic_not_writable",
        "characteristic_uuid": characteristic.uuid.uuidString
      ])
      log(.warning, "GATT DataX tx failed for \(label): DADA characteristic is not writable")
      return false
    }

    let writeType: CBCharacteristicWriteType = characteristic.properties.contains(.writeWithoutResponse)
      ? .withoutResponse
      : .withResponse
    let maximumLength = max(1, peripheral.maximumWriteValueLength(for: writeType))
    let chunks = stride(from: 0, to: data.count, by: maximumLength).map { offset in
      data[offset..<min(offset + maximumLength, data.count)]
    }
    guard !chunks.isEmpty else {
      sessionRecorder.record("gatt.datax.tx_failed", [
        "label": label,
        "reason": "empty_payload",
        "characteristic_uuid": characteristic.uuid.uuidString
      ])
      return false
    }

    for (index, chunk) in chunks.enumerated() {
      peripheral.writeValue(chunk, for: characteristic, type: writeType)
      sessionRecorder.recordGATTDataXTX(
        characteristic: characteristic,
        service: characteristic.service,
        byteCount: chunk.count,
        data: dumpRawFrames ? chunk : nil,
        label: label,
        chunkIndex: index,
        chunkCount: chunks.count
      )
    }
    log(.success, "GATT DataX tx \(label) bytes=\(data.count) chunks=\(chunks.count) characteristic=\(characteristic.uuid.uuidString)")
    return true
  }

  @discardableResult
  func sendL2CAPData(_ data: Data, label: String) -> Bool {
    guard let output = l2capOutputStream else {
      sessionRecorder.record("l2cap.tx_failed", [
        "label": label,
        "reason": "no_output_stream",
        "bytes_requested": data.count,
        "frame_fingerprint": Self.shortSHA256Fingerprint(data)
      ])
      log(.error, "L2CAP tx failed for \(label): no output stream")
      return false
    }
    guard output.streamStatus == .open || output.streamStatus == .writing else {
      sessionRecorder.record("l2cap.tx_failed", [
        "label": label,
        "reason": "stream_not_open",
        "bytes_requested": data.count,
        "frame_fingerprint": Self.shortSHA256Fingerprint(data),
        "stream_status": output.streamStatus.rawValue,
        "stream_status_description": L2CAPSession.streamStatusDescription(output.streamStatus)
      ])
      log(.error, "L2CAP tx failed for \(label): output stream not open")
      return false
    }
    guard output.hasSpaceAvailable else {
      sessionRecorder.record("l2cap.tx_failed", [
        "label": label,
        "reason": "stream_has_no_space",
        "bytes_requested": data.count,
        "frame_fingerprint": Self.shortSHA256Fingerprint(data),
        "stream_status": output.streamStatus.rawValue,
        "stream_status_description": L2CAPSession.streamStatusDescription(output.streamStatus)
      ])
      log(.warning, "L2CAP tx deferred for \(label): output stream has no space")
      return false
    }

    var offset = 0
    let bytesWritten = data.withUnsafeBytes { rawBuffer -> Int in
      guard let baseAddress = rawBuffer.bindMemory(to: UInt8.self).baseAddress else {
        return 0
      }
      while offset < data.count {
        let written = output.write(baseAddress.advanced(by: offset), maxLength: data.count - offset)
        if written <= 0 {
          return offset
        }
        offset += written
      }
      return offset
    }

    sessionRecorder.recordL2CAPTX(
      byteCount: bytesWritten,
      data: dumpRawFrames ? data.prefix(bytesWritten) : nil,
      label: label
    )
    if bytesWritten == data.count {
      var txDataXDecoder = DataXFrameDecoder()
      let txFrames = txDataXDecoder.append(data)
      for frame in txFrames {
        sessionRecorder.recordDecodedDataXFrame(
          frame,
          eventName: "datax.tx_frame",
          extraFields: [
            "transport": "l2cap",
            "label": label
          ]
        )
      }
      if dumpRawFrames {
        log(.success, "L2CAP tx \(label) bytes=\(data.count) hex=\(data.hexString)")
      } else {
        log(.success, "L2CAP tx \(label) bytes=\(data.count) rawHexSuppressed=true")
      }
      return true
    } else {
      sessionRecorder.record("l2cap.tx_failed", [
        "label": label,
        "bytes_requested": data.count,
        "bytes_written": bytesWritten,
        "frame_fingerprint": Self.shortSHA256Fingerprint(data),
        "error": output.streamError?.localizedDescription ?? "unknown"
      ])
      log(.error, "L2CAP tx incomplete for \(label): wrote \(bytesWritten)/\(data.count)")
      return false
    }
  }

  func log(_ level: BluetoothLogLevel, _ message: String) {
    let entry = BluetoothLogEntry(level: level, line: "[\(Self.timestampString())] \(message)")
    logEntries.append(entry)
    if logEntries.count > 500 {
      logEntries.removeFirst(logEntries.count - 500)
    }

    let json: [String: Any] = [
      "ts": isoFormatter.string(from: entry.date),
      "session_id": sessionID.uuidString,
      "level": level.rawValue,
      "message": message
    ]
    if let data = try? JSONSerialization.data(withJSONObject: json),
       let newline = "\n".data(using: .utf8) {
      logHandle?.write(data)
      logHandle?.write(newline)
    }
  }

  static func timestampString() -> String {
    let formatter = DateFormatter()
    formatter.dateFormat = "HH:mm:ss"
    return formatter.string(from: Date())
  }

  static func advertisementSummary(_ advertisementData: [String: Any]) -> String {
    BandScanner.advertisementSummary(advertisementData)
  }

  static func propertiesDescription(_ properties: CBCharacteristicProperties) -> String {
    GattSession.propertiesDescription(properties)
  }
}
