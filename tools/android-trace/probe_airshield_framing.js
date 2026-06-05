'use strict';

function hexToBytes(hex) {
  const normalized = String(hex || '').replace(/\s+/g, '');
  if (normalized.length % 2 !== 0) {
    throw new Error('hex string has odd length');
  }
  const out = [];
  for (let i = 0; i < normalized.length; i += 2) {
    out.push(parseInt(normalized.slice(i, i + 2), 16) & 0xff);
  }
  return Java.array('byte', out);
}

function bytesToHex(bytes, maxBytes) {
  if (!bytes) {
    return '';
  }
  const length = Math.min(bytes.length, maxBytes || bytes.length);
  const parts = [];
  for (let index = 0; index < length; index++) {
    parts.push(('0' + ((bytes[index] & 0xff).toString(16))).slice(-2));
  }
  return parts.join('');
}

function byteArraySummary(bytes, maxPrefixBytes) {
  if (!bytes) {
    return { length: null, prefixHex: '', sha256PrefixHex: null };
  }
  try {
    const MessageDigest = Java.use('java.security.MessageDigest');
    const digest = MessageDigest.getInstance('SHA-256');
    return {
      length: bytes.length,
      prefixHex: bytesToHex(bytes, maxPrefixBytes || 8),
      sha256PrefixHex: bytesToHex(digest.digest(bytes), 8)
    };
  } catch (error) {
    return {
      length: bytes.length,
      prefixHex: bytesToHex(bytes, maxPrefixBytes || 8),
      sha256PrefixHex: null,
      error: String(error)
    };
  }
}

function readBuffer(buffer) {
  const limit = buffer.position();
  const duplicate = buffer.duplicate();
  duplicate.position(0);
  duplicate.limit(limit);
  const out = [];
  while (duplicate.hasRemaining()) {
    out.push(duplicate.get());
  }
  return Java.array('byte', out);
}

function byteArraySlice(bytes, start) {
  const out = [];
  if (!bytes) {
    return Java.array('byte', out);
  }
  for (let index = start; index < bytes.length; index++) {
    out.push(bytes[index]);
  }
  return Java.array('byte', out);
}

function nativePaddedLength(plaintextLength) {
  const remainder = plaintextLength % 16;
  return remainder === 0 ? plaintextLength : plaintextLength + (16 - remainder);
}

rpc.exports = {
  probe: function(config) {
    let result = null;
    Java.perform(function() {
      const ByteBuffer = Java.use('java.nio.ByteBuffer');
      const PrivateKey = Java.use('com.facebook.wearable.airshield.security.PrivateKey');
      const PublicKey = Java.use('com.facebook.wearable.airshield.security.PublicKey');
      const InitializationVector = Java.use('com.facebook.wearable.airshield.security.InitializationVector');
      const CipherBuilder = Java.use('com.facebook.wearable.airshield.stream.CipherBuilder');

      const challenge = hexToBytes(config.challengeHex);
      const seed = hexToBytes(config.seedHex);
      const ivBytes = hexToBytes(config.initializationVectorHex);
      const plaintext = hexToBytes(config.plaintextHex);
      const localPrivateRaw = config.localPrivateKeyHex ? hexToBytes(config.localPrivateKeyHex) : null;
      const remotePrivateRaw = config.remotePrivateKeyHex ? hexToBytes(config.remotePrivateKeyHex) : null;
      const remotePublicRaw = config.remotePublicKeyHex ? hexToBytes(config.remotePublicKeyHex) : null;

      result = {
        schema: 'codex_airshield_framing_probe_v1',
        inputs: {
          challenge: byteArraySummary(challenge, 8),
          seed: byteArraySummary(seed, 8),
          initializationVector: byteArraySummary(ivBytes, 8),
          plaintext: byteArraySummary(plaintext, 8),
          base: config.base,
          usesHKDF: !!config.usesHKDF
        },
        localPrivateKey: null,
        localPublicKey: null,
        remotePrivateKey: null,
        remotePublicKey: null,
        txChallenge: null,
        rxChallenge: null,
        pack: null,
        errors: []
      };

      try {
        const builder = CipherBuilder.$new();

        if (localPrivateRaw) {
          const localPrivate = PrivateKey.$new();
          localPrivate.setRaw(localPrivateRaw);
          builder.setPrivateKey(localPrivate);
          result.localPrivateKey = byteArraySummary(localPrivate.serialize(), 8);
          result.localPublicKey = byteArraySummary(localPrivate.recoverPublicKey().serialize(), 8);
        } else {
          result.localPrivateKey = byteArraySummary(builder.getPrivateKey().serialize(), 8);
          result.localPublicKey = byteArraySummary(builder.getPublicKey().serialize(), 8);
        }

        let remotePublic = null;
        if (remotePrivateRaw) {
          const remotePrivate = PrivateKey.$new();
          remotePrivate.setRaw(remotePrivateRaw);
          remotePublic = remotePrivate.recoverPublicKey();
          result.remotePrivateKey = byteArraySummary(remotePrivate.serialize(), 8);
          result.remotePublicKey = byteArraySummary(remotePublic.serialize(), 8);
        } else if (remotePublicRaw) {
          remotePublic = PublicKey.from(remotePublicRaw);
          result.remotePublicKey = byteArraySummary(remotePublic.serialize(), 8);
        } else {
          throw new Error('remotePrivateKeyHex or remotePublicKeyHex is required');
        }

        const iv = InitializationVector.$new();
        iv.setRaw(ivBytes);

        builder.setChallenge(challenge);
        builder.setSeed(seed);
        builder.setInitializationVector(iv);
        builder.setRemotePublicKey(remotePublic);

        try {
          result.txChallenge = byteArraySummary(builder.buildTxChallenge().toByteArray(), 8);
        } catch (txError) {
          result.errors.push({ step: 'build_tx_challenge', error: String(txError) });
        }
        try {
          result.rxChallenge = byteArraySummary(builder.buildRxChallenge().toByteArray(), 8);
        } catch (rxError) {
          result.errors.push({ step: 'build_rx_challenge', error: String(rxError) });
        }

        const framing = builder.buildEncryptionFraming(config.base | 0, !!config.usesHKDF);
        const inputBuffer = ByteBuffer.allocateDirect(plaintext.length);
        inputBuffer.put(plaintext);
        inputBuffer.flip();

        const outerCapacity = plaintext.length + 64;
        const outputBuffer = ByteBuffer.allocateDirect(outerCapacity);
        const status = framing.pack(inputBuffer, outputBuffer);
        const outerFrame = readBuffer(outputBuffer);
        const expectedPaddedPlaintextLength = nativePaddedLength(plaintext.length);
        const expectedCipherPayloadLength = expectedPaddedPlaintextLength;
        const expectedOuterFrameLength = 9 + expectedCipherPayloadLength;
        const actualCipherPayloadLength = outerFrame.length > 9 ? outerFrame.length - 9 : 0;
        const actualSizeIndicator = outerFrame.length > 8 ? (outerFrame[8] & 0xff) : null;
        const expectedSizeIndicator = expectedCipherPayloadLength > 0
          ? Math.floor((expectedCipherPayloadLength - 1) / 16)
          : null;
        result.pack = {
          status: status ? String(status.toString()) : null,
          inputPosition: inputBuffer.position(),
          outputPosition: outputBuffer.position(),
          expectedPaddedPlaintextLength: expectedPaddedPlaintextLength,
          expectedCipherPayloadLength: expectedCipherPayloadLength,
          expectedOuterFrameLength: expectedOuterFrameLength,
          expectedSizeIndicator: expectedSizeIndicator,
          actualCipherPayloadLength: actualCipherPayloadLength,
          actualOuterFrameLength: outerFrame.length,
          actualSizeIndicator: actualSizeIndicator,
          inputFullyConsumed: inputBuffer.position() === plaintext.length,
          outputLengthMatchesExpected: outerFrame.length === expectedOuterFrameLength,
          cipherPayloadLengthMatchesExpected: actualCipherPayloadLength === expectedCipherPayloadLength,
          sizeIndicatorMatchesExpected: actualSizeIndicator === expectedSizeIndicator,
          outerFrame: byteArraySummary(outerFrame, 16),
          validationPrefixHex: bytesToHex(outerFrame, 8),
          sizeIndicatorHex: outerFrame.length > 8 ? ('0' + ((outerFrame[8] & 0xff).toString(16))).slice(-2) : null,
          cipherPayload: outerFrame.length > 9
            ? byteArraySummary(byteArraySlice(outerFrame, 9), 8)
            : null
        };
      } catch (error) {
        result.errors.push({ step: 'probe', error: String(error) });
      }
    });
    return result;
  }
};
