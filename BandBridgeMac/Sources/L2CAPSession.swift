import Foundation

enum L2CAPSession {
  static let minimumDynamicLEPSM: UInt16 = 0x0080
  static let maximumDynamicLEPSM: UInt16 = 0x00ff

  static func parsePSMText(_ text: String) -> UInt16? {
    let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else {
      return nil
    }

    if trimmed.lowercased().hasPrefix("0x") {
      return UInt16(trimmed.dropFirst(2), radix: 16)
    }
    return UInt16(trimmed, radix: 10)
  }

  static func isDynamicLEPSM(_ psm: UInt16) -> Bool {
    psm >= minimumDynamicLEPSM && psm <= maximumDynamicLEPSM
  }

  static func streamStatusDescription(_ status: Stream.Status) -> String {
    switch status {
    case .notOpen:
      return "notOpen"
    case .opening:
      return "opening"
    case .open:
      return "open"
    case .reading:
      return "reading"
    case .writing:
      return "writing"
    case .atEnd:
      return "atEnd"
    case .closed:
      return "closed"
    case .error:
      return "error"
    @unknown default:
      return "unknown"
    }
  }
}
