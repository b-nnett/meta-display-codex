import Foundation
import CoreBluetooth

final class SessionRecorder {
  let sessionID: UUID
  let eventFilePath: String
  let summaryFilePath: String

  private let eventHandle: FileHandle?
  private let isoFormatter = ISO8601DateFormatter()
  private var summary: [String: Any]

  init(sessionID: UUID, logDirectory: URL) {
    self.sessionID = sessionID
    let sessionDirectory = logDirectory.appendingPathComponent("sessions", isDirectory: true)
    try? FileManager.default.createDirectory(at: sessionDirectory, withIntermediateDirectories: true)
    let baseName = "session-\(sessionID.uuidString)"
    let eventURL = sessionDirectory.appendingPathComponent("\(baseName).jsonl")
    let summaryURL = sessionDirectory.appendingPathComponent("\(baseName)-summary.json")
    if !FileManager.default.fileExists(atPath: eventURL.path) {
      FileManager.default.createFile(atPath: eventURL.path, contents: nil)
    }
    self.eventFilePath = eventURL.path
    self.summaryFilePath = summaryURL.path
    self.eventHandle = try? FileHandle(forWritingTo: eventURL)
    self.eventHandle?.seekToEndOfFile()
    self.summary = [
      "session_id": sessionID.uuidString,
      "started_at": isoFormatter.string(from: Date()),
      "target_band_name": BluetoothScanner.exactBandName,
      "connection": [:],
      "scan": [
        "active": false,
        "started_count": 0,
        "stopped_count": 0,
        "candidate_count": 0,
        "exact_band_seen_count": 0
      ],
      "device": [:],
      "gatt": [
        "services": [],
        "characteristics": [],
        "psm_values": [],
        "errors": [],
        "datax_rx_count": 0,
        "datax_tx_count": 0,
        "datax_tx_failed_count": 0,
        "protected_access_error_count": 0
      ],
      "l2cap": [
        "active": false,
        "opened_psms": [],
        "rx_frame_count": 0,
        "tx_frame_count": 0,
        "closed_count": 0,
        "tx_failed_count": 0,
        "direct_write_diagnostic_started_count": 0,
        "direct_write_diagnostic_finished_count": 0,
        "direct_write_diagnostic_timeout_count": 0,
        "direct_write_diagnostic_blocked_count": 0
      ],
      "airshield": [
        "rx_candidate_match_count": 0,
        "rx_candidate_miss_count": 0,
        "identity_loaded_count": 0,
        "identity_imported_count": 0,
        "request_encryption_probe_ready_count": 0,
        "enable_trust_candidate_prepared_count": 0,
        "enable_trust_candidate_unavailable_count": 0,
        "enable_inputs_ready_count": 0,
        "enable_trust_gate_loaded_count": 0,
        "enable_trust_tx_ready_count": 0,
        "enable_trust_tx_sent_count": 0,
        "end_link_setup_tx_ready_count": 0,
        "end_link_setup_tx_sent_count": 0,
        "gesture_enable_tx_ready_count": 0,
        "gesture_enable_tx_sent_count": 0
      ],
      "wis": [
        "stream_control_response_count": 0,
        "stream_control_update_count": 0,
        "gesture_stream_active_count": 0,
        "decoded_gesture_count": 0
      ],
      "control": [
        "direct_write_trigger_ready_count": 0,
        "direct_write_trigger_received_count": 0,
        "direct_write_trigger_blocked_count": 0,
        "rescan_trigger_ready_count": 0,
        "rescan_trigger_received_count": 0,
        "rescan_trigger_blocked_count": 0
      ]
    ]
    writeSummary()
  }

  deinit {
    eventHandle?.closeFile()
  }

  func record(_ type: String, _ fields: [String: Any] = [:]) {
    var object: [String: Any] = [
      "ts": isoFormatter.string(from: Date()),
      "session_id": sessionID.uuidString,
      "type": type
    ]
    for (key, value) in fields {
      object[key] = value
    }
    writeJSONLine(object)
    updateDerivedSummary(type: type, fields: fields)
  }

  func recordDiscovery(_ item: DiscoveredPeripheral) {
    record("ble.discovery", [
      "peripheral_id": item.id.uuidString,
      "name": item.displayName,
      "rssi": item.rssi,
      "is_candidate": item.isCandidate,
      "is_exact_band": item.isExactBand,
      "advertisement": item.advertisementSummary
    ])
  }

  func recordConnection(_ type: String, peripheral: CBPeripheral, name: String, error: String? = nil) {
    var fields: [String: Any] = [
      "peripheral_id": peripheral.identifier.uuidString,
      "name": name
    ]
    if let error {
      fields["error"] = error
    }
    record(type, fields)
    var summaryFields = fields
    summaryFields["event"] = type
    updateConnectionSummary(summaryFields)
    if type == "ble.connected" {
      updateDevice([
        "peripheral_id": peripheral.identifier.uuidString,
        "name": name
      ])
    }
  }

  func recordConnectTimeout(
    peripheralID: UUID,
    name: String,
    reason: String,
    timeoutSeconds: Double,
    consecutiveTimeouts: Int
  ) {
    let fields: [String: Any] = [
      "reason": reason,
      "peripheral_id": peripheralID.uuidString,
      "name": name,
      "timeout_seconds": timeoutSeconds,
      "consecutive_timeouts": consecutiveTimeouts
    ]
    record("ble.connect_timeout", fields)
    var summaryFields = fields
    summaryFields["event"] = "ble.connect_timeout"
    updateConnectionSummary(summaryFields)
  }

  func recordServices(_ services: [CBService]) {
    let serviceIDs = services.map { $0.uuid.uuidString }
    record("gatt.services", ["services": serviceIDs])
    updateGATTArray(key: "services", values: serviceIDs)
  }

  func recordCharacteristic(_ characteristic: CBCharacteristic, service: CBService, properties: String) {
    let row: [String: Any] = [
      "service_uuid": service.uuid.uuidString,
      "characteristic_uuid": characteristic.uuid.uuidString,
      "properties": properties
    ]
    record("gatt.characteristic", row)
    appendGATTObject(key: "characteristics", row)
  }

  func recordCharacteristicValue(_ characteristic: CBCharacteristic, service: CBService?, value: Data) {
    var fields: [String: Any] = [
      "characteristic_uuid": characteristic.uuid.uuidString,
      "hex": value.hexString
    ]
    if let service {
      fields["service_uuid"] = service.uuid.uuidString
    }
    let ascii = value.printableASCII
    if !ascii.isEmpty {
      fields["ascii"] = ascii
    }
    if value.count == 2 {
      let psm = UInt16(value[0]) | (UInt16(value[1]) << 8)
      fields["possible_psm_le"] = Int(psm)
      appendPSM(["source": characteristic.uuid.uuidString, "psm": Int(psm), "raw_hex": value.hexString])
    }
    if let deviceInfoField = GattSession.deviceInfoField(for: characteristic.uuid), !ascii.isEmpty {
      updateDevice([deviceInfoField: ascii])
    }
    record("gatt.value", fields)
  }

  func recordCharacteristicError(_ characteristic: CBCharacteristic, service: CBService?, error: Error) {
    var fields: [String: Any] = [
      "characteristic_uuid": characteristic.uuid.uuidString,
      "error": error.localizedDescription
    ]
    if let service {
      fields["service_uuid"] = service.uuid.uuidString
    }
    let lowercased = error.localizedDescription.lowercased()
    if lowercased.contains("authentication is insufficient")
      || lowercased.contains("encryption is insufficient") {
      fields["protected_access_required"] = true
      incrementGATTInt("protected_access_error_count")
      updateGATTObject(key: "last_protected_access_error", fields)
    }
    appendGATTObject(key: "errors", fields)
    record("gatt.error", fields)
  }

  func recordGATTDataXRX(characteristic: CBCharacteristic, service: CBService?, value: Data, decodedFrameCount: Int) {
    var fields: [String: Any] = [
      "characteristic_uuid": characteristic.uuid.uuidString,
      "byte_count": value.count,
      "decoded_frame_count": decodedFrameCount
    ]
    if let service {
      fields["service_uuid"] = service.uuid.uuidString
    }
    if value.count > 0 {
      fields["hex"] = value.hexString
    }
    incrementGATTInt("datax_rx_count")
    updateGATTObject(key: "last_datax_rx", fields)
    record("gatt.datax.rx", fields)
  }

  func recordGATTDataXTX(
    characteristic: CBCharacteristic,
    service: CBService?,
    byteCount: Int,
    data: Data?,
    label: String,
    chunkIndex: Int,
    chunkCount: Int
  ) {
    var fields: [String: Any] = [
      "characteristic_uuid": characteristic.uuid.uuidString,
      "byte_count": byteCount,
      "label": label,
      "chunk_index": chunkIndex,
      "chunk_count": chunkCount
    ]
    if let service {
      fields["service_uuid"] = service.uuid.uuidString
    }
    if let data {
      fields["hex"] = data.hexString
    }
    incrementGATTInt("datax_tx_count")
    updateGATTObject(key: "last_datax_tx", fields)
    record("gatt.datax.tx", fields)
  }

  func recordL2CAPOpen(psm: UInt16) {
    record("l2cap.open", ["psm": Int(psm)])
    appendOpenedPSM(psm)
    updateL2CAPSummary([
      "active": true,
      "current_psm": Int(psm),
      "last_open": [
        "event": "l2cap.open",
        "psm": Int(psm)
      ]
    ])
  }

  func recordReconnectSkipped(_ fields: [String: Any]) {
    record("ble.reconnect_skipped", fields)
    var summaryFields = fields
    summaryFields["event"] = "ble.reconnect_skipped"
    updateConnectionSummary(summaryFields)
  }

  func recordL2CAPRX(byteCount: Int, data: Data?, decodedFrameCount: Int) {
    var fields: [String: Any] = [
      "byte_count": byteCount,
      "decoded_frame_count": decodedFrameCount
    ]
    if let data {
      fields["hex"] = data.hexString
    }
    incrementL2CAPCounter("rx_frame_count")
    record("l2cap.rx", fields)
  }

  func recordL2CAPTX(byteCount: Int, data: Data?, label: String) {
    var fields: [String: Any] = [
      "byte_count": byteCount,
      "label": label
    ]
    if let data {
      fields["hex"] = data.hexString
    }
    incrementL2CAPCounter("tx_frame_count")
    record("l2cap.tx", fields)
  }

  func recordDecodedDataXFrame(
    _ frame: DataXFrame,
    eventName: String = "datax.frame",
    extraFields: [String: Any] = [:]
  ) {
    var fields: [String: Any] = [
      "total_length": frame.totalLength,
      "body_length": frame.bodyLength,
      "base_id": Int(frame.baseID),
      "has_extensions": frame.hasExtensions,
      "reserved_header_bit14": frame.reservedHeaderBit14,
      "payload_length": frame.payload.count,
      "payload_fingerprint": frame.payloadFingerprint
    ]
    if let appID = frame.decodedAppID {
      fields["app_id"] = Int(appID)
    }
    if let messageType = frame.decodedMessageType {
      fields["message_type"] = Int(messageType)
    }
    if let channelAlias = frame.channelAlias {
      fields["channel_alias"] = Int(channelAlias)
    }
    if let typedBufferType = frame.typedBufferType {
      fields["typed_buffer_type"] = Int(typedBufferType)
    }
    if let airShieldTypedMessage = frame.airShieldTypedMessage {
      fields["airshield_typed_message"] = String(describing: airShieldTypedMessage)
    }
    if case .requestEncryption(let request)? = frame.decodedAirShieldMessage {
      var requestFields: [String: Any] = [:]
      requestFields["public_key_length"] = request.publicKey?.count ?? 0
      requestFields["challenge_length"] = request.challenge?.count ?? 0
      requestFields["elliptic_curve"] = request.ellipticCurve.map { Int($0) } ?? -1
      requestFields["supported_parameters"] = request.supportedParameters.map { Int($0) } ?? -1
      requestFields["uses_hkdf"] = request.usesHKDF
      requestFields["key_hint_count"] = request.keyHints.count
      requestFields["quirks"] = request.quirks.map { Int($0) } ?? -1
      requestFields["airshield_version"] = request.airShieldVersion.map { Int($0) } ?? -1
      fields["airshield_request_encryption"] = requestFields
    }
    if let authServiceName = frame.airShieldAuthServiceName {
      fields["airshield_auth_service"] = authServiceName
    }
    if let authTypedBufferName = frame.airShieldAuthTypedBufferName {
      fields["airshield_auth_typed_buffer"] = authTypedBufferName
    }
    if let authPayload = frame.decodedAirShieldAuthPayload {
      fields["airshield_auth_payload"] = authPayload.logFields
    }
    fields["extensions"] = frame.extensions.map { word in
      [
        "type": Int(word.type),
        "has_continuation": word.hasContinuation,
        "auxiliary": Int(word.auxiliary),
        "value": Int(word.value)
      ]
    }
    for (key, value) in extraFields {
      fields[key] = value
    }
    record(eventName, fields)
  }

  func recordAirShieldCandidateMatch(_ fields: [String: Any]) {
    record("airshield.encrypted.rx_candidate_matched", fields)
    incrementAirShieldCounter("rx_candidate_match_count")
    updateAirShieldSummary([
      "last_rx_match": fields
    ])
  }

  func recordAirShieldCandidateMiss(_ fields: [String: Any]) {
    record("airshield.encrypted.rx_candidate_miss", fields)
    incrementAirShieldCounter("rx_candidate_miss_count")
    updateAirShieldSummary([
      "last_rx_miss": fields
    ])
  }

  func recordAirShieldEnableInputsReady(_ fields: [String: Any]) {
    record("airshield.enable_inputs_ready", fields)
    incrementAirShieldCounter("enable_inputs_ready_count")
    updateAirShieldSummary([
      "last_enable_inputs_ready": fields
    ])
  }

  func recordAirShieldIdentityLoaded(_ fields: [String: Any]) {
    record("airshield.identity.loaded", fields)
    incrementAirShieldCounter("identity_loaded_count")
    updateAirShieldSummary([
      "last_identity": fields,
      "last_identity_source": "loaded"
    ])
  }

  func recordAirShieldIdentityImported(_ fields: [String: Any]) {
    record("airshield.identity.imported", fields)
    incrementAirShieldCounter("identity_imported_count")
    updateAirShieldSummary([
      "last_identity": fields,
      "last_identity_source": "imported"
    ])
  }

  func recordAirShieldProbeStateReady(_ fields: [String: Any]) {
    record("airshield.probe_state_ready", fields)
    incrementAirShieldCounter("request_encryption_probe_ready_count")
    updateAirShieldSummary([
      "last_request_encryption_probe": fields
    ])
  }

  func recordAirShieldEnableTrustCandidatesPrepared(_ fields: [String: Any]) {
    record("airshield.identity.enable_trust_candidates_prepared", fields)
    incrementAirShieldCounter("enable_trust_candidate_prepared_count")
    updateAirShieldSummary([
      "last_enable_trust_candidates_prepared": fields
    ])
  }

  func recordAirShieldEnableTrustCandidatesUnavailable(_ fields: [String: Any]) {
    record("airshield.identity.enable_trust_candidates_unavailable", fields)
    incrementAirShieldCounter("enable_trust_candidate_unavailable_count")
    updateAirShieldSummary([
      "last_enable_trust_candidates_unavailable": fields
    ])
  }

  func recordAirShieldGestureEnableReady(_ fields: [String: Any]) {
    record("airshield.gesture_enable.tx_ready", fields)
    incrementAirShieldCounter("gesture_enable_tx_ready_count")
    updateAirShieldSummary([
      "last_gesture_enable_tx_ready": fields
    ])
  }

  func recordAirShieldGestureEnableSent(_ fields: [String: Any]) {
    record("airshield.gesture_enable.tx_sent", fields)
    incrementAirShieldCounter("gesture_enable_tx_sent_count")
    updateAirShieldSummary([
      "last_gesture_enable_tx_sent": fields
    ])
  }

  func recordAirShieldEndLinkSetupReady(_ fields: [String: Any]) {
    record("airshield.end_link_setup.tx_ready", fields)
    incrementAirShieldCounter("end_link_setup_tx_ready_count")
    updateAirShieldSummary([
      "last_end_link_setup_tx_ready": fields
    ])
  }

  func recordAirShieldEndLinkSetupSent(_ fields: [String: Any]) {
    record("airshield.end_link_setup.tx_sent", fields)
    incrementAirShieldCounter("end_link_setup_tx_sent_count")
    updateAirShieldSummary([
      "last_end_link_setup_tx_sent": fields
    ])
  }

  func recordAirShieldEnableTrustGateLoaded(_ fields: [String: Any]) {
    record("airshield.identity.enable_trust_gate_loaded", fields)
    incrementAirShieldCounter("enable_trust_gate_loaded_count")
    updateAirShieldSummary([
      "last_enable_trust_gate_loaded": fields
    ])
  }

  func recordAirShieldEnableTrustReady(_ fields: [String: Any]) {
    record("airshield.identity.enable_trust.tx_ready", fields)
    incrementAirShieldCounter("enable_trust_tx_ready_count")
    updateAirShieldSummary([
      "last_enable_trust_tx_ready": fields
    ])
  }

  func recordAirShieldEnableTrustSent(_ fields: [String: Any]) {
    record("airshield.identity.enable_trust.tx_sent", fields)
    incrementAirShieldCounter("enable_trust_tx_sent_count")
    updateAirShieldSummary([
      "last_enable_trust_tx_sent": fields
    ])
  }

  func recordWISStreamControlResponse(_ fields: [String: Any]) {
    record("wis.stream_control.response", fields)
    incrementWISCounter("stream_control_response_count")
    updateWISSummary(["last_stream_control_response": fields])
    if fields["gesture_stream_active"] as? Bool == true {
      incrementWISCounter("gesture_stream_active_count")
      updateWISSummary(["last_gesture_stream_active": fields])
    }
  }

  func recordWISStreamControlUpdate(_ fields: [String: Any]) {
    record("wis.stream_control.update", fields)
    incrementWISCounter("stream_control_update_count")
    updateWISSummary(["last_stream_control_update": fields])
    if fields["gesture_stream_active"] as? Bool == true {
      incrementWISCounter("gesture_stream_active_count")
      updateWISSummary(["last_gesture_stream_active": fields])
    }
  }

  func recordDecodedGesture(_ fields: [String: Any]) {
    record("datax.gesture_decoded", fields)
    incrementWISCounter("decoded_gesture_count")
    updateWISSummary(["last_decoded_gesture": fields])
  }

  private func updateDevice(_ fields: [String: Any]) {
    var device = summary["device"] as? [String: Any] ?? [:]
    for (key, value) in fields {
      device[key] = value
    }
    summary["device"] = device
    writeSummary()
  }

  private func updateConnectionSummary(_ fields: [String: Any]) {
    var connection = summary["connection"] as? [String: Any] ?? [:]
    for (key, value) in fields {
      connection[key] = value
    }
    summary["connection"] = connection
    writeSummary()
  }

  private func updateGATTArray(key: String, values: [Any]) {
    var gatt = summary["gatt"] as? [String: Any] ?? [:]
    gatt[key] = values
    summary["gatt"] = gatt
    writeSummary()
  }

  private func appendGATTObject(key: String, _ value: [String: Any]) {
    var gatt = summary["gatt"] as? [String: Any] ?? [:]
    var values = gatt[key] as? [[String: Any]] ?? []
    values.append(value)
    gatt[key] = values
    summary["gatt"] = gatt
    writeSummary()
  }

  private func updateGATTObject(key: String, _ value: [String: Any]) {
    var gatt = summary["gatt"] as? [String: Any] ?? [:]
    gatt[key] = value
    summary["gatt"] = gatt
    writeSummary()
  }

  private func incrementGATTInt(_ key: String) {
    var gatt = summary["gatt"] as? [String: Any] ?? [:]
    let current = gatt[key] as? Int ?? 0
    gatt[key] = current + 1
    summary["gatt"] = gatt
    writeSummary()
  }

  private func appendPSM(_ value: [String: Any]) {
    var gatt = summary["gatt"] as? [String: Any] ?? [:]
    var values = gatt["psm_values"] as? [[String: Any]] ?? []
    values.append(value)
    gatt["psm_values"] = values
    summary["gatt"] = gatt
    writeSummary()
  }

  private func appendOpenedPSM(_ psm: UInt16) {
    var l2cap = summary["l2cap"] as? [String: Any] ?? [:]
    var psms = l2cap["opened_psms"] as? [Int] ?? []
    if !psms.contains(Int(psm)) {
      psms.append(Int(psm))
    }
    l2cap["opened_psms"] = psms
    summary["l2cap"] = l2cap
    writeSummary()
  }

  private func incrementL2CAPCounter(_ key: String) {
    var l2cap = summary["l2cap"] as? [String: Any] ?? [:]
    l2cap[key] = (l2cap[key] as? Int ?? 0) + 1
    summary["l2cap"] = l2cap
    writeSummary()
  }

  private func updateL2CAPSummary(_ fields: [String: Any]) {
    var l2cap = summary["l2cap"] as? [String: Any] ?? [:]
    for (key, value) in fields {
      l2cap[key] = value
    }
    summary["l2cap"] = l2cap
    writeSummary()
  }

  private func updateDerivedSummary(type: String, fields: [String: Any]) {
    switch type {
    case "l2cap.closed":
      var row = fields
      row["event"] = type
      incrementL2CAPCounter("closed_count")
      updateL2CAPSummary([
        "active": false,
        "last_closed": row
      ])
    case "l2cap.tx_failed":
      var row = fields
      row["event"] = type
      incrementL2CAPCounter("tx_failed_count")
      updateL2CAPSummary(["last_tx_failed": row])
    case "l2cap.direct_write_diagnostic_started":
      var row = fields
      row["event"] = type
      incrementL2CAPCounter("direct_write_diagnostic_started_count")
      updateL2CAPSummary(["last_direct_write_diagnostic": row])
    case "l2cap.direct_write_diagnostic_finished":
      var row = fields
      row["event"] = type
      incrementL2CAPCounter("direct_write_diagnostic_finished_count")
      updateL2CAPSummary(["last_direct_write_diagnostic": row])
    case "l2cap.direct_write_diagnostic_timeout":
      var row = fields
      row["event"] = type
      incrementL2CAPCounter("direct_write_diagnostic_timeout_count")
      updateL2CAPSummary(["last_direct_write_diagnostic": row])
    case "l2cap.direct_write_diagnostic_blocked":
      var row = fields
      row["event"] = type
      incrementL2CAPCounter("direct_write_diagnostic_blocked_count")
      updateL2CAPSummary(["last_direct_write_diagnostic": row])
    case "gatt.datax.tx_failed":
      var row = fields
      row["event"] = type
      incrementGATTInt("datax_tx_failed_count")
      updateGATTObject(key: "last_datax_tx_failed", row)
    case "ble.scan_started":
      var row = fields
      row["event"] = type
      incrementScanCounter("started_count")
      updateScanSummary([
        "active": true,
        "last_started": row,
        "candidate_count": 0,
        "exact_band_seen_count": 0
      ])
    case "ble.scan_stopped":
      var row = fields
      row["event"] = type
      incrementScanCounter("stopped_count")
      updateScanSummary([
        "active": false,
        "last_stopped": row
      ])
    case "ble.discovery":
      var row = fields
      row["event"] = type
      if fields["is_candidate"] as? Bool == true {
        incrementScanCounter("candidate_count")
        updateScanSummary(["last_candidate": row])
      }
      if fields["is_exact_band"] as? Bool == true {
        incrementScanCounter("exact_band_seen_count")
        updateScanSummary(["last_exact_band": row])
      }
    case "control.direct_write_trigger_ready":
      var row = fields
      row["event"] = type
      incrementControlCounter("direct_write_trigger_ready_count")
      updateControlSummary(["last_direct_write_trigger_ready": row])
    case "control.direct_write_trigger_received":
      var row = fields
      row["event"] = type
      incrementControlCounter("direct_write_trigger_received_count")
      updateControlSummary(["last_direct_write_trigger_received": row])
    case "control.direct_write_trigger_blocked":
      var row = fields
      row["event"] = type
      incrementControlCounter("direct_write_trigger_blocked_count")
      updateControlSummary(["last_direct_write_trigger_blocked": row])
    case "control.rescan_trigger_ready":
      var row = fields
      row["event"] = type
      incrementControlCounter("rescan_trigger_ready_count")
      updateControlSummary(["last_rescan_trigger_ready": row])
    case "control.rescan_trigger_received":
      var row = fields
      row["event"] = type
      incrementControlCounter("rescan_trigger_received_count")
      updateControlSummary(["last_rescan_trigger_received": row])
    case "control.rescan_trigger_blocked":
      var row = fields
      row["event"] = type
      incrementControlCounter("rescan_trigger_blocked_count")
      updateControlSummary(["last_rescan_trigger_blocked": row])
    default:
      break
    }
  }

  private func incrementAirShieldCounter(_ key: String) {
    var airShield = summary["airshield"] as? [String: Any] ?? [:]
    airShield[key] = (airShield[key] as? Int ?? 0) + 1
    summary["airshield"] = airShield
    writeSummary()
  }

  private func updateAirShieldSummary(_ fields: [String: Any]) {
    var airShield = summary["airshield"] as? [String: Any] ?? [:]
    for (key, value) in fields {
      airShield[key] = value
    }
    summary["airshield"] = airShield
    writeSummary()
  }

  private func incrementWISCounter(_ key: String) {
    var wis = summary["wis"] as? [String: Any] ?? [:]
    wis[key] = (wis[key] as? Int ?? 0) + 1
    summary["wis"] = wis
    writeSummary()
  }

  private func updateWISSummary(_ fields: [String: Any]) {
    var wis = summary["wis"] as? [String: Any] ?? [:]
    for (key, value) in fields {
      wis[key] = value
    }
    summary["wis"] = wis
    writeSummary()
  }

  private func incrementControlCounter(_ key: String) {
    var control = summary["control"] as? [String: Any] ?? [:]
    control[key] = (control[key] as? Int ?? 0) + 1
    summary["control"] = control
    writeSummary()
  }

  private func updateControlSummary(_ fields: [String: Any]) {
    var control = summary["control"] as? [String: Any] ?? [:]
    for (key, value) in fields {
      control[key] = value
    }
    summary["control"] = control
    writeSummary()
  }

  private func incrementScanCounter(_ key: String) {
    var scan = summary["scan"] as? [String: Any] ?? [:]
    scan[key] = (scan[key] as? Int ?? 0) + 1
    summary["scan"] = scan
    writeSummary()
  }

  private func updateScanSummary(_ fields: [String: Any]) {
    var scan = summary["scan"] as? [String: Any] ?? [:]
    for (key, value) in fields {
      scan[key] = value
    }
    summary["scan"] = scan
    writeSummary()
  }

  private func writeJSONLine(_ object: [String: Any]) {
    guard let data = try? JSONSerialization.data(withJSONObject: object),
          let newline = "\n".data(using: .utf8) else {
      return
    }
    eventHandle?.write(data)
    eventHandle?.write(newline)
  }

  private func writeSummary() {
    guard JSONSerialization.isValidJSONObject(summary),
          let data = try? JSONSerialization.data(withJSONObject: summary, options: [.prettyPrinted, .sortedKeys]) else {
      return
    }
    try? data.write(to: URL(fileURLWithPath: summaryFilePath))
  }

}
