import Foundation

func fail(_ message: String) -> Never {
  fputs("FAIL: \(message)\n", stderr)
  exit(1)
}

func jsonString(_ value: String) -> String {
  var output = "\""
  for scalar in value.unicodeScalars {
    switch scalar {
    case "\"":
      output += "\\\""
    case "\\":
      output += "\\\\"
    case "\n":
      output += "\\n"
    case "\r":
      output += "\\r"
    case "\t":
      output += "\\t"
    default:
      if scalar.value < 0x20 {
        output += String(format: "\\u%04x", scalar.value)
      } else {
        output.unicodeScalars.append(scalar)
      }
    }
  }
  output += "\""
  return output
}

@main
struct EmitAirShieldFirstWriteVector {
  static func main() throws {
    let publicKey = Data((0..<64).map { UInt8(($0 + 1) & 0xff) })
    let challenge = Data((0..<16).map { UInt8(0xa0 + $0) })
    let payload = AirShieldLinkSetup.encodeRequestEncryption(
      publicKey: publicKey,
      challenge: challenge
    )
    let frame = try AirShieldLinkSetup.encodeDataXFrame(
      typedMessage: .requestEncryption,
      payload: payload,
      baseID: NativeDataXLocalChannel.baseID(localChannelID: 0)
    )

    var decoder = DataXFrameDecoder()
    let decodedFrames = decoder.append(frame)
    guard decodedFrames.count == 1, let decodedFrame = decodedFrames.first else {
      fail("expected one decoded DataX frame")
    }
    guard decodedFrame.baseID == 0x8000 else {
      fail("unexpected base id \(decodedFrame.baseID)")
    }
    guard decodedFrame.extensions.count == 2 else {
      fail("expected service and typed-buffer extensions")
    }
    guard decodedFrame.extensions[0].type == 1,
          decodedFrame.extensions[0].value == AirShieldLinkSetup.dataXServiceID else {
      fail("missing AirShield service extension")
    }
    guard decodedFrame.extensions[1].type == 2,
          decodedFrame.extensions[1].value == AirShieldLinkSetup.TypedMessage.requestEncryption.rawValue else {
      fail("missing RequestEncryption typed-buffer extension")
    }
    guard case .requestEncryption(let decodedRequest) = AirShieldLinkSetup.decode(
      typedMessage: .requestEncryption,
      payload: decodedFrame.payload
    ) else {
      fail("RequestEncryption payload did not decode")
    }
    guard decodedRequest.publicKey == publicKey,
          decodedRequest.challenge == challenge,
          decodedRequest.ellipticCurve == 0,
          decodedRequest.supportedParameters == 1 else {
      fail("RequestEncryption decoded fields do not match vector inputs")
    }
    guard payload.shortSHA256Fingerprint == "5524a47ec81421ed" else {
      fail("unexpected RequestEncryption payload fingerprint \(payload.shortSHA256Fingerprint)")
    }
    guard frame.shortSHA256Fingerprint == "5168a633f4a35471" else {
      fail("unexpected RequestEncryption DataX frame fingerprint \(frame.shortSHA256Fingerprint)")
    }
    guard frame.hexString == "8060800081000005020000010a400102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f401210a0a1a2a3a4a5a6a7a8a9aaabacadaeaf18002001" else {
      fail("unexpected RequestEncryption DataX frame bytes")
    }

    let lines = [
      "{",
      "  \"schema\": \"codex_band_bridge.airshield_first_write_vector.v1\",",
      "  \"description\": \"Deterministic non-secret AirShield RequestEncryption DataX first-write vector\",",
      "  \"base_id\": 32768,",
      "  \"local_channel_id\": 0,",
      "  \"service_id\": \(AirShieldLinkSetup.dataXServiceID),",
      "  \"typed_buffer_type\": \(AirShieldLinkSetup.TypedMessage.requestEncryption.rawValue),",
      "  \"typed_buffer_name\": \"REQUEST_ENCRYPTION\",",
      "  \"public_key_length\": \(publicKey.count),",
      "  \"public_key_fingerprint\": \(jsonString(publicKey.shortSHA256Fingerprint)),",
      "  \"challenge_length\": \(challenge.count),",
      "  \"challenge_fingerprint\": \(jsonString(challenge.shortSHA256Fingerprint)),",
      "  \"payload_length\": \(payload.count),",
      "  \"payload_fingerprint\": \(jsonString(payload.shortSHA256Fingerprint)),",
      "  \"frame_length\": \(frame.count),",
      "  \"frame_fingerprint\": \(jsonString(frame.shortSHA256Fingerprint)),",
      "  \"frame_hex\": \(jsonString(frame.hexString))",
      "}"
    ]
    print(lines.joined(separator: "\n"))
  }
}
