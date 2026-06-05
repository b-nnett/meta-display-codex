import Foundation
import CoreBluetooth

struct DiscoveredPeripheral: Identifiable, Hashable {
  let id: UUID
  var name: String?
  var rssi: Int
  var advertisementSummary: String
  var isCandidate: Bool
  var isExactBand: Bool

  var displayName: String {
    guard let name, !name.isEmpty else {
      return "Unnamed Peripheral"
    }
    return name
  }

  var candidatePriority: Int {
    let lowerName = displayName.lowercased()
    if isExactBand {
      return 4
    }
    if lowerName.hasPrefix("meta band") {
      return 3
    }
    if lowerName.hasPrefix("hwz_") {
      return 1
    }
    return isCandidate ? 2 : 0
  }
}

enum BandScanner {
  static let exactBandName = "Meta Band 000J"

  static func isExactTargetBand(name: String?) -> Bool {
    (name ?? "").caseInsensitiveCompare(exactBandName) == .orderedSame
  }

  static func isLikelyBand(name: String?, advertisementSummary: String) -> Bool {
    let lowerName = (name ?? "").lowercased()
    let lowerAdvertisement = advertisementSummary.lowercased()
    return lowerName.hasPrefix("hwz_")
      || lowerName.contains("meta")
      || lowerName.contains("neural")
      || lowerName.contains("band")
      || lowerName.contains("ceres")
      || lowerAdvertisement.contains("neural")
      || lowerAdvertisement.contains("ceres")
  }

  static func hasTargetBandServices(_ services: [CBService]) -> Bool {
    let serviceIDs = Set(services.map { $0.uuid.uuidString.uppercased() })
    return serviceIDs.contains("0000FEB8-0000-1000-8000-00805F9B34FB")
      || serviceIDs.contains("FD5F")
      || serviceIDs.contains("0000EFF0-0000-0000-8000-34635C9B94FB")
      || (serviceIDs.contains("180F") && serviceIDs.contains("180A"))
  }

  static func advertisementSummary(_ advertisementData: [String: Any]) -> String {
    let volatileKeys: Set<String> = [
      "kCBAdvDataTimestamp",
      "kCBAdvDataRxPrimaryPHY",
      "kCBAdvDataRxSecondaryPHY"
    ]

    return advertisementData.keys.sorted().compactMap { key in
      if volatileKeys.contains(key) {
        return nil
      }
      let value = advertisementData[key]
      if let data = value as? Data {
        return "\(key)=\(data.hexString)"
      }
      if let uuids = value as? [CBUUID] {
        return "\(key)=\(uuids.map { $0.uuidString }.joined(separator: ","))"
      }
      return "\(key)=\(String(describing: value ?? "nil"))"
    }
    .joined(separator: " ")
  }
}
