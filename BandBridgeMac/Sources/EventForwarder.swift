import Foundation

struct ForwardedGestureEvent: Identifiable, Hashable {
  let id = UUID()
  var date: Date
  var action: String
  var finger: String
  var sequenceNumber: UInt64?
  var timestamp: UInt64?
  var source: String

  var summary: String {
    var parts = [
      action,
      "finger=\(finger)",
      "source=\(source)"
    ]
    if let sequenceNumber {
      parts.append("seq=\(sequenceNumber)")
    }
    if let timestamp {
      parts.append("timestamp=\(timestamp)")
    }
    return parts.joined(separator: " ")
  }
}

final class EventForwarder {
  static let notificationName = Notification.Name("com.example.codexbandbridge.gesture")
  static let payloadSchema = "codex_band_bridge.gesture.v1"
  static let httpPaths = ["/health", "/schema", "/latest", "/events", "/events.ndjson"]
  static let httpMethods = ["GET", "OPTIONS"]
  static let liveValidationActions = [
    "tap",
    "double_tap",
    "swipe_up",
    "swipe_down",
    "swipe_in",
    "swipe_out",
    "press",
    "hold",
    "release"
  ]
  static let standardActions = [
    "tap",
    "double_tap",
    "swipe_up",
    "swipe_down",
    "swipe_left",
    "swipe_right",
    "press",
    "release"
  ]
  static let requiredPayloadFields = [
    "schema",
    "event_type",
    "ts",
    "action",
    "normalized_action",
    "finger",
    "source",
    "frame_base_id",
    "frame_payload_hex",
    "app_id",
    "message_type"
  ]
  static let optionalPayloadFields = [
    "channel_alias",
    "typed_buffer_type",
    "sequence_number",
    "timestamp",
    "raw_finger",
    "raw_action",
    "derived_action",
    "emg_batch_id_low",
    "emg_batch_id_high",
    "imu_sequence_number",
    "device_latency_micros",
    "inference_trigger_emg_offset",
    "emg_raw_gesture_id",
    "is_synthetic_gesture"
  ]
  static let routeAppID = Int(WISProtocol.AppID.emgImu.rawValue)
  static let routeMessageType = Int(WISProtocol.MessageType.gesture.rawValue)

  let eventFilePath: String
  let socketEndpoint: String
  let webSocketEndpoint: String
  let httpEndpoint: String
  let lanHTTPEndpoint: String

  private let localServer = LocalEventServer()
  private let webSocketServer = LocalWebSocketEventServer()
  private let httpServer = LocalHTTPEventServer()
  private let lanHTTPServer: LocalHTTPEventServer?
  private let handle: FileHandle?
  private let isoFormatter = ISO8601DateFormatter()

  init(logDirectory: URL) {
    let eventURL = logDirectory.appendingPathComponent("gesture-events.jsonl")
    if !FileManager.default.fileExists(atPath: eventURL.path) {
      FileManager.default.createFile(atPath: eventURL.path, contents: nil)
    }
    self.eventFilePath = eventURL.path
    self.socketEndpoint = localServer.endpoint
    self.webSocketEndpoint = webSocketServer.endpoint
    self.httpEndpoint = httpServer.endpoint
    if Self.isLANForwardingEnabled {
      let lanHTTPServer = LocalHTTPEventServer(
        port: 49734,
        bindAddress: "0.0.0.0",
        displayHost: LocalHTTPEventServer.preferredLANIPv4Address() ?? "0.0.0.0",
        allowWildcardCORS: false
      )
      self.lanHTTPServer = lanHTTPServer
      self.lanHTTPEndpoint = lanHTTPServer.endpoint
    } else {
      self.lanHTTPServer = nil
      self.lanHTTPEndpoint = "LAN forwarding disabled"
    }
    self.handle = try? FileHandle(forWritingTo: eventURL)
    self.handle?.seekToEndOfFile()
  }

  deinit {
    handle?.closeFile()
  }

  func forward(
    _ gesture: GestureEvent,
    source: String,
    frame: DataXFrame
  ) -> ForwardedGestureEvent {
    let now = Date()
    let event = ForwardedGestureEvent(
      date: now,
      action: gesture.normalizedAction,
      finger: gesture.fingerName,
      sequenceNumber: gesture.sequenceNumber,
      timestamp: gesture.timestamp,
      source: source
    )
    let json = Self.payloadJSON(gesture: gesture, source: source, frame: frame, date: now)

    writeJSONLine(json)
    postNotification(json)
    localServer.broadcast(json)
    webSocketServer.broadcast(json)
    httpServer.record(json)
    lanHTTPServer?.record(Self.redactedPayloadForLAN(json))
    return event
  }

  static func payloadJSON(
    gesture: GestureEvent,
    source: String,
    frame: DataXFrame,
    date: Date,
    formatter: ISO8601DateFormatter = ISO8601DateFormatter()
  ) -> [String: Any] {
    var json: [String: Any] = [
      "schema": payloadSchema,
      "event_type": "gesture",
      "ts": formatter.string(from: date),
      "action": gesture.normalizedAction,
      "normalized_action": gesture.normalizedAction,
      "finger": gesture.fingerName,
      "source": source,
      "frame_base_id": frame.baseID,
      "frame_payload_hex": frame.payload.hexString,
    ]
    if let channelAlias = frame.channelAlias {
      json["channel_alias"] = channelAlias
    }
    if let typedBufferType = frame.typedBufferType {
      json["typed_buffer_type"] = typedBufferType
    }
    if let appID = frame.decodedAppID {
      json["app_id"] = appID
    }
    if let messageType = frame.decodedMessageType {
      json["message_type"] = messageType
    }
    if let sequenceNumber = gesture.sequenceNumber {
      json["sequence_number"] = sequenceNumber
    }
    if let timestamp = gesture.timestamp {
      json["timestamp"] = timestamp
    }
    if let finger = gesture.finger {
      json["raw_finger"] = finger
    }
    if let rawAction = gesture.action {
      json["raw_action"] = rawAction
    }
    if let derivedAction = gesture.derivedAction {
      json["derived_action"] = derivedAction
    }
    if let emgBatchIDLow = gesture.emgBatchIDLow {
      json["emg_batch_id_low"] = emgBatchIDLow
    }
    if let emgBatchIDHigh = gesture.emgBatchIDHigh {
      json["emg_batch_id_high"] = emgBatchIDHigh
    }
    if let imuSequenceNumber = gesture.imuSequenceNumber {
      json["imu_sequence_number"] = imuSequenceNumber
    }
    if let deviceLatencyMicros = gesture.deviceLatencyMicros {
      json["device_latency_micros"] = deviceLatencyMicros
    }
    if let inferenceTriggerEMGOffset = gesture.inferenceTriggerEMGOffset {
      json["inference_trigger_emg_offset"] = inferenceTriggerEMGOffset
    }
    if let rawGestureID = gesture.emgRawGestureID {
      json["emg_raw_gesture_id"] = rawGestureID
    }
    if let isSyntheticGesture = gesture.isSyntheticGesture {
      json["is_synthetic_gesture"] = isSyntheticGesture
    }
    return json
  }

  private static var isLANForwardingEnabled: Bool {
    let environment = ProcessInfo.processInfo.environment
    return environment["CODEX_BAND_BRIDGE_ENABLE_LAN"] == "1"
      || UserDefaults.standard.bool(forKey: "CodexBandBridgeEnableLAN")
  }

  private static func redactedPayloadForLAN(_ json: [String: Any]) -> [String: Any] {
    var redacted = json
    redacted.removeValue(forKey: "frame_payload_hex")
    redacted["frame_payload_redacted"] = true
    return redacted
  }

  static func sessionPayloadJSON(
    gesture: GestureEvent,
    source: String,
    frame: DataXFrame,
    frameSource: String,
    date: Date,
    formatter: ISO8601DateFormatter = ISO8601DateFormatter()
  ) -> [String: Any] {
    var json = payloadJSON(
      gesture: gesture,
      source: source,
      frame: frame,
      date: date,
      formatter: formatter
    )
    json["frame_source"] = frameSource
    return json
  }

  private func writeJSONLine(_ json: [String: Any]) {
    guard let data = try? JSONSerialization.data(withJSONObject: json),
          let newline = "\n".data(using: .utf8) else {
      return
    }
    handle?.write(data)
    handle?.write(newline)
  }

  private func postNotification(_ json: [String: Any]) {
    let userInfo = json.reduce(into: [String: String]()) { result, item in
      result[item.key] = String(describing: item.value)
    }
    DistributedNotificationCenter.default().postNotificationName(
      Self.notificationName,
      object: nil,
      userInfo: userInfo,
      deliverImmediately: true
    )
  }
}
