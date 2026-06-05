import Foundation

struct GestureEvent: Hashable, CustomStringConvertible {
  var sequenceNumber: UInt64?
  var timestamp: UInt64?
  var finger: UInt64?
  var action: UInt64?
  var derivedAction: UInt64?
  var emgBatchIDLow: UInt64?
  var emgBatchIDHigh: UInt64?
  var imuSequenceNumber: UInt64?
  var deviceLatencyMicros: UInt64?
  var inferenceTriggerEMGOffset: UInt64?
  var emgRawGestureID: UInt64?
  var isSyntheticGesture: Bool?

  var normalizedAction: String {
    if let derivedAction {
      switch derivedAction {
      case 1: return "tap"
      case 2: return "double_tap"
      case 3: return "hold"
      case 4: return "release"
      case 5: return "swipe_up"
      case 6: return "swipe_down"
      case 7: return "swipe_left"
      case 8: return "swipe_right"
      case 9: return "press"
      case 10: return "hold_release"
      default: break
      }
    }

    guard let action else {
      return "unknown"
    }
    switch action {
    case 1: return "press"
    case 2: return "release"
    case 3: return "tap"
    case 4: return "double_tap"
    case 5: return "click"
    case 6: return "swipe_up"
    case 7: return "swipe_down"
    case 8: return "swipe_left"
    case 9: return "swipe_right"
    case 10: return "wake"
    case 11: return "swipe_in"
    case 12: return "swipe_out"
    case 13: return "meta_ai"
    case 14: return "partial_press"
    case 15: return "partial_release"
    case 16: return "partial_click"
    case 17: return "partial_up"
    case 18: return "partial_down"
    case 19: return "partial_left"
    case 20: return "partial_right"
    default: return "action_\(action)"
    }
  }

  var fingerName: String {
    guard let finger else {
      return "unknown"
    }
    switch finger {
    case 1: return "thumb"
    case 2: return "index"
    case 3: return "middle"
    case 4: return "not_applicable"
    default: return "finger_\(finger)"
    }
  }

  var description: String {
    var parts = [
      "Gesture",
      "event=\(normalizedAction)",
      "finger=\(fingerName)"
    ]
    if let sequenceNumber {
      parts.append("seq=\(sequenceNumber)")
    }
    if let timestamp {
      parts.append("timestamp=\(timestamp)")
    }
    if let action {
      parts.append("action=\(action)")
    }
    if let derivedAction {
      parts.append("derived=\(derivedAction)")
    }
    if let emgRawGestureID {
      parts.append("rawGestureID=\(emgRawGestureID)")
    }
    if let isSyntheticGesture {
      parts.append("synthetic=\(isSyntheticGesture)")
    }
    return parts.joined(separator: " ")
  }
}

enum GestureEventDecoder {
  static func decode(_ data: Data) -> GestureEvent? {
    var reader = ProtoReader(data)
    var event = GestureEvent()
    var sawGestureField = false

    while let field = reader.nextField() {
      switch field.number {
      case 1:
        event.sequenceNumber = reader.readVarint()
        sawGestureField = true
      case 2:
        event.timestamp = reader.readVarint()
        sawGestureField = true
      case 3:
        event.finger = reader.readVarint()
        sawGestureField = true
      case 4:
        event.action = reader.readVarint()
        sawGestureField = true
      case 5:
        event.derivedAction = reader.readVarint()
        sawGestureField = true
      case 6:
        event.emgBatchIDLow = reader.readVarint()
      case 7:
        event.emgBatchIDHigh = reader.readVarint()
      case 8:
        event.imuSequenceNumber = reader.readVarint()
      case 9:
        event.deviceLatencyMicros = reader.readVarint()
      case 10:
        event.inferenceTriggerEMGOffset = reader.readVarint()
      case 11:
        event.emgRawGestureID = reader.readVarint()
      case 12:
        event.isSyntheticGesture = (reader.readVarint() ?? 0) != 0
      default:
        reader.skip(wireType: field.wireType)
      }
    }

    return sawGestureField ? event : nil
  }
}
