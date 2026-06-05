import Foundation

enum FramingProbeCompareError: Error, CustomStringConvertible {
  case missingArgument
  case unreadableJSON
  case missingSecretMaterial
  case missingHex(String)
  case invalidHex(String)
  case noCandidates
  case selfTestFailed(String)

  var description: String {
    switch self {
    case .missingArgument:
      return "usage: CompareAirShieldFramingProbe /path/to/airshield-framing-probe.json | --json /path/to/airshield-framing-probe.json | --self-test | --self-test-probe-json"
    case .unreadableJSON:
      return "unable to read probe JSON"
    case .missingSecretMaterial:
      return "probe JSON lacks secretMaterial; rerun probe_airshield_framing.py with --include-secret-material for synthetic comparison"
    case .missingHex(let key):
      return "missing hex field \(key)"
    case .invalidHex(let key):
      return "invalid hex field \(key)"
    case .noCandidates:
      return "Swift produced no synthetic framing candidates"
    case .selfTestFailed(let message):
      return "self-test failed: \(message)"
    }
  }
}

let fullMatchScore = 18
let fullMatchLabels = Set([
  "local_public_key",
  "remote_public_key",
  "validation_prefix",
  "cipher_payload",
  "outer_frame"
])

func dictionary(_ value: Any?) -> [String: Any]? {
  value as? [String: Any]
}

func stringValue(_ value: Any?) -> String? {
  guard let value else { return nil }
  if value is NSNull {
    return nil
  }
  return String(describing: value)
}

func jsonString(_ value: String?) -> Any {
  value ?? NSNull()
}

func displayString(_ value: Any?) -> String {
  guard let text = stringValue(value), !text.isEmpty else {
    return "-"
  }
  return text
}

func boolValue(_ value: Any?) -> Bool {
  if let value = value as? Bool {
    return value
  }
  if let value = value as? NSNumber {
    return value.boolValue
  }
  return false
}

func uint32Value(_ value: Any?) -> UInt32 {
  if let value = value as? UInt32 {
    return value
  }
  if let value = value as? Int {
    return UInt32(truncatingIfNeeded: value)
  }
  if let value = value as? NSNumber {
    return UInt32(truncatingIfNeeded: value.uint64Value)
  }
  if let value = value as? String {
    return UInt32(value, radix: value.hasPrefix("0x") ? 16 : 10) ?? 0
  }
  return 0
}

func dataFromHex(_ value: String, key: String) throws -> Data {
  let cleaned = value.filter { !$0.isWhitespace }
  guard cleaned.count.isMultiple(of: 2) else {
    throw FramingProbeCompareError.invalidHex(key)
  }
  var data = Data()
  data.reserveCapacity(cleaned.count / 2)
  var index = cleaned.startIndex
  while index < cleaned.endIndex {
    let next = cleaned.index(index, offsetBy: 2)
    guard let byte = UInt8(cleaned[index..<next], radix: 16) else {
      throw FramingProbeCompareError.invalidHex(key)
    }
    data.append(byte)
    index = next
  }
  return data
}

func requiredHex(_ secret: [String: Any], _ key: String) throws -> Data {
  guard let text = stringValue(secret[key]), !text.isEmpty else {
    throw FramingProbeCompareError.missingHex(key)
  }
  return try dataFromHex(text, key: key)
}

func fingerprintMatches(_ left: String?, _ right: String?) -> Bool {
  guard let left, let right, !left.isEmpty, !right.isEmpty else {
    return false
  }
  return left.lowercased().hasPrefix(right.lowercased()) || right.lowercased().hasPrefix(left.lowercased())
}

func score(
  candidate: AirShieldSyntheticFramingProbeCandidate,
  nativeLocalPublicKeyFingerprint: String?,
  nativeRemotePublicKeyFingerprint: String?,
  nativePrefix: String?,
  nativeCipherFingerprint: String?,
  nativeOuterFingerprint: String?
) -> (points: Int, matches: [String], mismatches: [String]) {
  var points = 0
  var matches: [String] = []
  var mismatches: [String] = []
  if fingerprintMatches(candidate.localPublicKeyFingerprint, nativeLocalPublicKeyFingerprint) {
    points += 2
    matches.append("local_public_key")
  } else if nativeLocalPublicKeyFingerprint != nil {
    points -= 2
    mismatches.append("local_public_key")
  }
  if fingerprintMatches(candidate.remotePublicKeyFingerprint, nativeRemotePublicKeyFingerprint) {
    points += 2
    matches.append("remote_public_key")
  } else if nativeRemotePublicKeyFingerprint != nil {
    points -= 2
    mismatches.append("remote_public_key")
  }
  if candidate.frame.summary.validationPrefixHex == nativePrefix {
    points += 6
    matches.append("validation_prefix")
  } else if nativePrefix != nil {
    points -= 4
    mismatches.append("validation_prefix")
  }
  if fingerprintMatches(candidate.frame.summary.cipherPayloadFingerprint, nativeCipherFingerprint) {
    points += 4
    matches.append("cipher_payload")
  } else if nativeCipherFingerprint != nil {
    points -= 3
    mismatches.append("cipher_payload")
  }
  if fingerprintMatches(candidate.frame.summary.outerFrameFingerprint, nativeOuterFingerprint) {
    points += 4
    matches.append("outer_frame")
  } else if nativeOuterFingerprint != nil {
    points -= 3
    mismatches.append("outer_frame")
  }
  return (points, matches, mismatches)
}

func syntheticProbeCandidatesFromSecret(_ secret: [String: Any]) throws -> [AirShieldSyntheticFramingProbeCandidate] {
  try AirShieldSession.syntheticFramingProbeCandidates(
    localPrivateKeyRaw: requiredHex(secret, "localPrivateKeyHex"),
    remotePrivateKeyRaw: stringValue(secret["remotePrivateKeyHex"]).flatMap {
      try? dataFromHex($0, key: "remotePrivateKeyHex")
    },
    remotePublicKeyRaw: stringValue(secret["remotePublicKeyHex"]).flatMap {
      try? dataFromHex($0, key: "remotePublicKeyHex")
    },
    localChallenge: requiredHex(secret, "challengeHex"),
    seed: requiredHex(secret, "seedHex"),
    initializationVector: requiredHex(secret, "initializationVectorHex"),
    plaintext: requiredHex(secret, "plaintextHex"),
    base: uint32Value(secret["base"]),
    usesHKDF: boolValue(secret["usesHKDF"])
  )
}

func selfTestSecret() -> [String: Any] {
  [
    "localPrivateKeyHex": String(repeating: "0", count: 63) + "1",
    "remotePrivateKeyHex": String(repeating: "0", count: 63) + "2",
    "remotePublicKeyHex": "",
    "challengeHex": "00112233445566778899aabbccddeeff",
    "seedHex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "initializationVectorHex": "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
    "plaintextHex": "806080008100000502001000080110011a1050a68dfb8f45453396d60f2cd3528a3d",
    "base": 0,
    "usesHKDF": true
  ]
}

func summary(length: Int, fingerprint: String) -> [String: Any] {
  [
    "length": length,
    "prefixHex": "",
    "sha256PrefixHex": fingerprint
  ]
}

func selfTestProbeReport() throws -> [String: Any] {
  let secret = selfTestSecret()
  let candidates = try syntheticProbeCandidatesFromSecret(secret)
  guard let first = candidates.first else {
    throw FramingProbeCompareError.noCandidates
  }
  let plaintextLength = first.frame.summary.plaintextLength
  let cipherPayloadLength = first.frame.summary.cipherPayloadLength
  let outerFrameLength = first.frame.summary.outerFrameLength
  let sizeIndicator = cipherPayloadLength > 0 ? (cipherPayloadLength - 1) / 16 : 0
  return [
    "schema": "codex_airshield_framing_probe_report_v1_self_test",
    "createdAt": "self-test",
    "inputs": [
      "challenge": ["length": 16],
      "seed": ["length": 32],
      "initializationVector": ["length": 16],
      "plaintext": ["length": plaintextLength],
      "base": 0,
      "usesHKDF": true
    ],
    "native": [
      "schema": "codex_airshield_framing_probe_v1_self_test",
      "errors": [],
      "localPublicKey": summary(length: 64, fingerprint: first.localPublicKeyFingerprint),
      "remotePublicKey": summary(length: 64, fingerprint: first.remotePublicKeyFingerprint),
      "txChallenge": summary(length: 32, fingerprint: "selftesttx000000"),
      "rxChallenge": summary(length: 32, fingerprint: "selftestrx000000"),
      "pack": [
        "status": "SUCCESS",
        "inputPosition": plaintextLength,
        "outputPosition": outerFrameLength,
        "expectedPaddedPlaintextLength": cipherPayloadLength,
        "expectedCipherPayloadLength": cipherPayloadLength,
        "expectedOuterFrameLength": outerFrameLength,
        "expectedSizeIndicator": sizeIndicator,
        "actualCipherPayloadLength": cipherPayloadLength,
        "actualOuterFrameLength": outerFrameLength,
        "actualSizeIndicator": sizeIndicator,
        "inputFullyConsumed": true,
        "outputLengthMatchesExpected": true,
        "cipherPayloadLengthMatchesExpected": true,
        "sizeIndicatorMatchesExpected": true,
        "validationPrefixHex": first.frame.summary.validationPrefixHex,
        "outerFrame": summary(
          length: outerFrameLength,
          fingerprint: first.frame.summary.outerFrameFingerprint
        ),
        "cipherPayload": summary(
          length: cipherPayloadLength,
          fingerprint: first.frame.summary.cipherPayloadFingerprint
        )
      ]
    ],
    "secretMaterial": secret
  ]
}

func runSelfTest() throws {
  let candidates = try syntheticProbeCandidatesFromSecret(selfTestSecret())
  guard let first = candidates.first else {
    throw FramingProbeCompareError.noCandidates
  }
  let result = score(
    candidate: first,
    nativeLocalPublicKeyFingerprint: first.localPublicKeyFingerprint,
    nativeRemotePublicKeyFingerprint: first.remotePublicKeyFingerprint,
    nativePrefix: first.frame.summary.validationPrefixHex,
    nativeCipherFingerprint: first.frame.summary.cipherPayloadFingerprint,
    nativeOuterFingerprint: first.frame.summary.outerFrameFingerprint
  )
  guard result.points == fullMatchScore else {
    throw FramingProbeCompareError.selfTestFailed("expected score \(fullMatchScore), got \(result.points)")
  }
  guard Set(result.matches) == fullMatchLabels, result.mismatches.isEmpty else {
    throw FramingProbeCompareError.selfTestFailed(
      "unexpected matches=\(result.matches) mismatches=\(result.mismatches)"
    )
  }
  print("self-test: OK")
}

func comparisonReport(from root: [String: Any]) throws -> [String: Any] {
  guard let secret = dictionary(root["secretMaterial"]) else {
    throw FramingProbeCompareError.missingSecretMaterial
  }
  let native = dictionary(root["native"])
  let pack = dictionary(native?["pack"])
  let nativeLocalPublicKeyFingerprint = stringValue(dictionary(native?["localPublicKey"])?["sha256PrefixHex"])
  let nativeRemotePublicKeyFingerprint = stringValue(dictionary(native?["remotePublicKey"])?["sha256PrefixHex"])
  let nativePrefix = stringValue(pack?["validationPrefixHex"])
  let nativeCipherFingerprint = stringValue(dictionary(pack?["cipherPayload"])?["sha256PrefixHex"])
  let nativeOuterFingerprint = stringValue(dictionary(pack?["outerFrame"])?["sha256PrefixHex"])

  let candidates = try syntheticProbeCandidatesFromSecret(secret)
  guard !candidates.isEmpty else {
    throw FramingProbeCompareError.noCandidates
  }

  let ranked = candidates
    .map {
      (
        score(
          candidate: $0,
          nativeLocalPublicKeyFingerprint: nativeLocalPublicKeyFingerprint,
          nativeRemotePublicKeyFingerprint: nativeRemotePublicKeyFingerprint,
          nativePrefix: nativePrefix,
          nativeCipherFingerprint: nativeCipherFingerprint,
          nativeOuterFingerprint: nativeOuterFingerprint
        ),
        $0
      )
    }
    .sorted { $0.0.points > $1.0.points }
  let best = ranked[0]
  let fullMatch = best.0.points == fullMatchScore
    && Set(best.0.matches) == fullMatchLabels
    && best.0.mismatches.isEmpty

  return [
    "schema": "codex_airshield_framing_probe_comparison_v1",
    "candidate_count": candidates.count,
    "native": [
      "local_public_key_fingerprint": jsonString(nativeLocalPublicKeyFingerprint),
      "remote_public_key_fingerprint": jsonString(nativeRemotePublicKeyFingerprint),
      "validation_prefix_hex": jsonString(nativePrefix),
      "cipher_payload_fingerprint": jsonString(nativeCipherFingerprint),
      "outer_frame_fingerprint": jsonString(nativeOuterFingerprint),
    ],
    "best": [
      "score": best.0.points,
      "full_match": fullMatch,
      "source": best.1.sharedMaterialSource,
      "matches": best.0.matches,
      "mismatches": best.0.mismatches,
      "swift_local_public_key_fingerprint": best.1.localPublicKeyFingerprint,
      "swift_remote_public_key_fingerprint": best.1.remotePublicKeyFingerprint,
      "swift_validation_prefix_hex": best.1.frame.summary.validationPrefixHex,
      "swift_cipher_payload_fingerprint": best.1.frame.summary.cipherPayloadFingerprint,
      "swift_outer_frame_fingerprint": best.1.frame.summary.outerFrameFingerprint,
    ],
  ]
}

func loadRootJSON(path: String) throws -> [String: Any] {
  let url = URL(fileURLWithPath: path)
  let raw = try Data(contentsOf: url)
  guard let root = try JSONSerialization.jsonObject(with: raw) as? [String: Any] else {
    throw FramingProbeCompareError.unreadableJSON
  }
  return root
}

func printTextReport(_ report: [String: Any]) {
  let native = dictionary(report["native"]) ?? [:]
  let best = dictionary(report["best"]) ?? [:]
  print("Swift synthetic candidates: \(report["candidate_count"] ?? 0)")
  print("Native local public key fingerprint: \(displayString(native["local_public_key_fingerprint"]))")
  print("Native remote public key fingerprint: \(displayString(native["remote_public_key_fingerprint"]))")
  print("Native validation prefix: \(displayString(native["validation_prefix_hex"]))")
  print("Native cipher fingerprint: \(displayString(native["cipher_payload_fingerprint"]))")
  print("Native outer fingerprint: \(displayString(native["outer_frame_fingerprint"]))")
  print("")
  print("best_score=\(best["score"] ?? 0) full_match=\(best["full_match"] ?? false) source=\(displayString(best["source"]))")
  print("  matches: \((best["matches"] as? [String] ?? []).isEmpty ? "-" : (best["matches"] as? [String] ?? []).joined(separator: ", "))")
  print("  mismatches: \((best["mismatches"] as? [String] ?? []).isEmpty ? "-" : (best["mismatches"] as? [String] ?? []).joined(separator: ", "))")
  print("  swift local_public_key_fp=\(displayString(best["swift_local_public_key_fingerprint"])) remote_public_key_fp=\(displayString(best["swift_remote_public_key_fingerprint"]))")
  print("  swift prefix=\(displayString(best["swift_validation_prefix_hex"])) cipher_fp=\(displayString(best["swift_cipher_payload_fingerprint"])) outer_fp=\(displayString(best["swift_outer_frame_fingerprint"]))")
}

@main
struct CompareAirShieldFramingProbe {
  static func main() {
    do {
      let args = Array(CommandLine.arguments.dropFirst())
      guard !args.isEmpty else {
        throw FramingProbeCompareError.missingArgument
      }
      if args == ["--self-test"] {
        try runSelfTest()
        return
      }
      if args == ["--self-test-probe-json"] {
        let encoded = try JSONSerialization.data(
          withJSONObject: selfTestProbeReport(),
          options: [.prettyPrinted, .sortedKeys]
        )
        FileHandle.standardOutput.write(encoded)
        print("")
        return
      }
      let jsonOutput: Bool
      let path: String
      if args.count == 2 && args[0] == "--json" {
        jsonOutput = true
        path = args[1]
      } else if args.count == 1 {
        jsonOutput = false
        path = args[0]
      } else {
        throw FramingProbeCompareError.missingArgument
      }
      let report = try comparisonReport(from: loadRootJSON(path: path))
      if jsonOutput {
        let encoded = try JSONSerialization.data(withJSONObject: report, options: [.prettyPrinted, .sortedKeys])
        FileHandle.standardOutput.write(encoded)
        print("")
      } else {
        printTextReport(report)
      }
    } catch {
      fputs("FAIL: \(error)\n", stderr)
      exit(1)
    }
  }
}
