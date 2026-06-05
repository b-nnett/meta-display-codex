import Foundation
import CoreBluetooth

struct ServiceRow: Identifiable, Hashable {
  let id = UUID()
  var title: String
  var detail: String
}

enum GattSession {
  static func psmFromLittleEndianValue(_ value: Data) -> UInt16? {
    guard value.count == 2 else {
      return nil
    }
    return UInt16(value[0]) | (UInt16(value[1]) << 8)
  }

  static func deviceInfoField(for uuid: CBUUID) -> String? {
    switch uuid.uuidString.uppercased() {
    case "2A25":
      return "serial"
    case "2A26":
      return "firmware"
    case "2A29":
      return "manufacturer"
    case "2A24":
      return "model"
    default:
      return nil
    }
  }

  static func propertiesDescription(_ properties: CBCharacteristicProperties) -> String {
    var names: [String] = []
    if properties.contains(.broadcast) { names.append("broadcast") }
    if properties.contains(.read) { names.append("read") }
    if properties.contains(.writeWithoutResponse) { names.append("writeWithoutResponse") }
    if properties.contains(.write) { names.append("write") }
    if properties.contains(.notify) { names.append("notify") }
    if properties.contains(.indicate) { names.append("indicate") }
    if properties.contains(.authenticatedSignedWrites) { names.append("authenticatedSignedWrites") }
    if properties.contains(.extendedProperties) { names.append("extendedProperties") }
    if properties.contains(.notifyEncryptionRequired) { names.append("notifyEncryptionRequired") }
    if properties.contains(.indicateEncryptionRequired) { names.append("indicateEncryptionRequired") }
    return names.isEmpty ? "none" : names.joined(separator: ",")
  }
}
