'use strict';

const MAX_HEX_BYTES = 512;
const nativeHookedPointers = {};
const nativeInterestingNames = [
  'initializeNative',
  'startNative',
  'receiveDataNative',
  'receiveSingleFrameNative',
  'buildEncryptionFramingNative',
  'buildDecryptionFramingNative',
  'outerFrameSizeNative',
  'cipherPayloadSizeNative',
  'buildTxChallengeNative',
  'buildRxChallengeNative',
  'setPrivateKey',
  'setChallengeNative',
  'setSeedNative',
  'reinitializeNative'
];
const staticAirShieldMethods = [
  {
    className: 'com/facebook/wearable/airshield/stream/CipherBuilder',
    methodName: 'setPrivateKey',
    signature: '(J)V',
    offset: 0xda665c,
    source: 'jniThunk'
  },
  {
    className: 'com/facebook/wearable/airshield/stream/CipherBuilder',
    methodName: 'setChallengeNative',
    signature: '([B)V',
    offset: 0xda6668,
    source: 'jniThunk'
  },
  {
    className: 'com/facebook/wearable/airshield/stream/CipherBuilder',
    methodName: 'setSeedNative',
    signature: '([B)V',
    offset: 0xda6674,
    source: 'jniThunk'
  },
  {
    className: 'com/facebook/wearable/airshield/stream/CipherBuilder',
    methodName: 'setInitializationVectorNative',
    signature: '(J)V',
    offset: 0xda6680,
    source: 'jniThunk'
  },
  {
    className: 'com/facebook/wearable/airshield/stream/CipherBuilder',
    methodName: 'setRemotePublicKeyNative',
    signature: '(J)V',
    offset: 0xda668c,
    source: 'jniThunk'
  },
  {
    className: 'com/facebook/wearable/airshield/stream/CipherBuilder',
    methodName: 'buildRxChallengeNative',
    signature: '()Lcom/facebook/wearable/airshield/security/Hash;',
    offset: 0xda6698,
    source: 'jniThunk'
  },
  {
    className: 'com/facebook/wearable/airshield/stream/CipherBuilder',
    methodName: 'buildTxChallengeNative',
    signature: '()Lcom/facebook/wearable/airshield/security/Hash;',
    offset: 0xda66a4,
    source: 'jniThunk'
  },
  {
    className: 'com/facebook/wearable/airshield/stream/CipherBuilder',
    methodName: 'buildEncryptionFramingNative',
    signature: '(IZ)Lcom/facebook/wearable/airshield/stream/Framing;',
    offset: 0xda66b0,
    source: 'jniThunk'
  },
  {
    className: 'com/facebook/wearable/airshield/stream/CipherBuilder',
    methodName: 'buildDecryptionFramingNative',
    signature: '(IZ)Lcom/facebook/wearable/airshield/stream/Framing;',
    offset: 0xda66bc,
    source: 'jniThunk'
  },
  {
    className: 'com/facebook/wearable/airshield/stream/Framing',
    methodName: 'outerFrameSizeNative',
    signature: '(I)I',
    offset: 0xda7660,
    source: 'jniBody'
  },
  {
    className: 'com/facebook/wearable/airshield/stream/Framing',
    methodName: 'packNative',
    signature: '(Ljava/nio/ByteBuffer;IILjava/nio/ByteBuffer;II)I',
    offset: 0xda772c,
    source: 'jniBody'
  },
  {
    className: 'com/facebook/wearable/airshield/stream/Framing',
    methodName: 'unpackNative',
    signature: '(Ljava/nio/ByteBuffer;IILjava/nio/ByteBuffer;II)I',
    offset: 0xda774c,
    source: 'jniBody'
  },
  {
    className: 'com/facebook/wearable/airshield/stream/Framing',
    methodName: 'cipherPayloadSizeNative',
    signature: '(Ljava/nio/ByteBuffer;II)I',
    offset: 0xda776c,
    source: 'jniBody'
  },
  {
    className: 'com/facebook/wearable/airshield/stream/Framing',
    methodName: 'packFrameHelper',
    signature: 'native-helper',
    offset: 0xdb139c,
    source: 'nativeHelper',
    argStart: 0
  },
  {
    className: 'com/facebook/wearable/airshield/stream/Framing',
    methodName: 'unpackFrameHelper',
    signature: 'native-helper',
    offset: 0xdb15c4,
    source: 'nativeHelper',
    argStart: 0
  },
  {
    className: 'com/facebook/wearable/airshield/stream/Framing',
    methodName: 'validationPrefixModeHelper',
    signature: 'native-helper',
    offset: 0xdb1558,
    source: 'nativeHelper',
    argStart: 0
  },
  {
    className: 'com/facebook/wearable/airshield/stream/Framing',
    methodName: 'hmacSha256LikeHelper',
    signature: 'native-helper',
    offset: 0x62dbdc,
    source: 'nativeHelper',
    argStart: 0
  },
  {
    className: 'com/facebook/wearable/airshield/stream/Framing',
    methodName: 'sha256UpdateHelper',
    signature: 'native-helper',
    offset: 0x5d39a0,
    source: 'nativeHelper',
    argStart: 0
  },
  {
    className: 'com/facebook/wearable/airshield/stream/Framing',
    methodName: 'sha256FinalHelper',
    signature: 'native-helper',
    offset: 0x62e954,
    source: 'nativeHelper',
    argStart: 0
  },
  {
    className: 'com/facebook/wearable/airshield/stream/Framing',
    methodName: 'cipherTransformDispatch',
    signature: 'native-helper',
    offset: 0x64bf68,
    source: 'nativeHelper',
    argStart: 0
  },
  {
    className: 'com/facebook/wearable/airshield/stream/Framing',
    methodName: 'transformDescriptorLookup',
    signature: 'native-helper',
    offset: 0x64bf18,
    source: 'nativeHelper',
    argStart: 0
  },
  {
    className: 'com/facebook/wearable/airshield/stream/Framing',
    methodName: 'transformConfigureHelper',
    signature: 'native-helper',
    offset: 0x63327c,
    source: 'nativeHelper',
    argStart: 0
  },
  {
    className: 'com/facebook/wearable/airshield/stream/Framing',
    methodName: 'transformKeyMaterialSetter',
    signature: 'native-helper',
    offset: 0x64cfe0,
    source: 'nativeHelper',
    argStart: 0
  },
  {
    className: 'com/facebook/wearable/airshield/stream/Framing',
    methodName: 'streamTransformBufferedHelper',
    signature: 'native-helper',
    offset: 0x64c7d8,
    source: 'nativeHelper',
    argStart: 0
  },
  {
    className: 'com/facebook/wearable/airshield/stream/Framing',
    methodName: 'streamTransformXorBlockHelper',
    signature: 'native-helper',
    offset: 0x64c948,
    source: 'nativeHelper',
    argStart: 0
  },
  {
    className: 'com/facebook/wearable/airshield/stream/Framing',
    methodName: 'blockPrimitiveOrTweakSetupHelper',
    signature: 'native-helper',
    offset: 0x64c51c,
    source: 'nativeHelper',
    argStart: 0
  },
  {
    className: 'com/facebook/wearable/airshield/stream/Framing',
    methodName: 'blockPrimitiveRoundHelper',
    signature: 'native-helper',
    offset: 0x64c654,
    source: 'nativeHelper',
    argStart: 0
  },
  {
    className: 'com/facebook/wearable/airshield/stream/Framing',
    methodName: 'selectedMode2OutputPointerHelper',
    signature: 'native-helper',
    offset: 0xdb2dec,
    source: 'nativeHelper',
    argStart: 0
  },
  {
    className: 'com/facebook/wearable/airshield/stream/Framing',
    methodName: 'selectedFamily0BlockTransformHelper',
    signature: 'native-helper',
    offset: 0xdb2e24,
    source: 'nativeHelper',
    argStart: 0
  },
  {
    className: 'com/facebook/wearable/airshield/stream/Framing',
    methodName: 'selectedFamily0CtrLikeXorHelper',
    signature: 'native-helper',
    offset: 0xdb2f54,
    source: 'nativeHelper',
    argStart: 0
  },
  {
    className: 'com/facebook/wearable/airshield/stream/Framing',
    methodName: 'selectedFamily0KeyScheduleHelper',
    signature: 'native-helper',
    offset: 0xdb3064,
    source: 'nativeHelper',
    argStart: 0
  },
  {
    className: 'com/facebook/wearable/airshield/stream/CipherBuilder',
    methodName: 'challengeDigestDerivationHelper',
    signature: 'native-helper',
    offset: 0xd9bfd0,
    source: 'nativeHelper',
    argStart: 0
  },
  {
    className: 'com/facebook/wearable/airshield/stream/CipherBuilder',
    methodName: 'framingKeyDerivationHelper',
    signature: 'native-helper',
    offset: 0xdb17b4,
    source: 'nativeHelper',
    argStart: 0
  },
  {
    className: 'com/facebook/wearable/airshield/stream/CipherBuilder',
    methodName: 'hmacContextDigestHelper',
    signature: 'native-helper',
    offset: 0xd9a0cc,
    source: 'nativeHelper',
    argStart: 0
  },
  {
    className: 'com/facebook/wearable/airshield/stream/CipherBuilder',
    methodName: 'hmacContextInitWrapper',
    signature: 'native-helper',
    offset: 0xdb1b38,
    source: 'nativeHelper',
    argStart: 0
  },
  {
    className: 'com/facebook/wearable/airshield/stream/CipherBuilder',
    methodName: 'rxFramingStateSetupHelper',
    signature: 'native-helper',
    offset: 0xd9de60,
    source: 'nativeHelper',
    argStart: 0
  },
  {
    className: 'com/facebook/wearable/airshield/stream/Framing',
    methodName: 'framingConfigCopyHelper',
    signature: 'native-helper',
    offset: 0xdb12ec,
    source: 'nativeHelper',
    argStart: 0
  },
  {
    className: 'com/facebook/wearable/airshield/stream/Framing',
    methodName: 'cipherContextBuilderHelper',
    signature: 'native-helper',
    offset: 0xdb18d4,
    source: 'nativeHelper',
    argStart: 0
  }
];

function now() {
  return new Date().toISOString();
}

function log(event, fields) {
  const payload = Object.assign({ ts: now(), event: event }, fields || {});
  console.log(JSON.stringify(payload));
}

function signedByteToHex(value) {
  return ('0' + (value & 0xff).toString(16)).slice(-2);
}

function byteArrayToHex(bytes, maxBytes) {
  const limit = Math.min(bytes.length, maxBytes || MAX_HEX_BYTES);
  let hex = '';
  for (let i = 0; i < limit; i += 1) {
    hex += signedByteToHex(bytes[i]);
  }
  if (bytes.length > limit) {
    hex += '...';
  }
  return hex;
}

function javaByteArraySummary(bytes, maxPrefixBytes) {
  if (bytes === null || bytes === undefined) {
    return { length: 0, prefixHex: '', sha256PrefixHex: null };
  }

  try {
    const length = bytes.length;
    if (typeof length !== 'number') {
      return { length: null, prefixHex: '', sha256PrefixHex: null, error: 'not a byte array' };
    }

    let sha256 = null;
    try {
      const MessageDigest = Java.use('java.security.MessageDigest');
      const digest = MessageDigest.getInstance('SHA-256');
      sha256 = byteArrayToHex(digest.digest(bytes), 8);
    } catch (error) {
      sha256 = 'error:' + String(error);
    }

    return {
      length: length,
      prefixHex: byteArrayToHex(bytes, maxPrefixBytes || 8),
      sha256PrefixHex: sha256
    };
  } catch (error) {
    return { length: null, prefixHex: '', sha256PrefixHex: null, error: String(error) };
  }
}

function signedByte(value) {
  const normalized = value & 0xff;
  return normalized > 127 ? normalized - 256 : normalized;
}

function transcriptChallengeWindowSummary(challengeBytes) {
  if (challengeBytes === null || challengeBytes === undefined || challengeBytes.length < 8) {
    return { length: null, prefixHex: '', sha256PrefixHex: null, error: 'challenge shorter than 8 bytes' };
  }

  const window = [];
  for (let i = 0; i < 8; i += 1) {
    window.push(0);
  }
  for (let i = 0; i < 8; i += 1) {
    window.push(signedByte(challengeBytes[i]));
  }
  return javaByteArraySummary(Java.array('byte', window), 8);
}

function transcriptMaterialWindowSummary(seedBytes) {
  if (seedBytes === null || seedBytes === undefined || seedBytes.length < 24) {
    return { length: null, prefixHex: '', sha256PrefixHex: null, error: 'seed shorter than 24 bytes' };
  }

  const window = [1, 0, 0, 0, 0, 0, 0, 0];
  for (let i = 0; i < 24; i += 1) {
    window.push(signedByte(seedBytes[i]));
  }
  return javaByteArraySummary(Java.array('byte', window), 8);
}

function airShieldHashSummary(hashObject) {
  if (hashObject === null || hashObject === undefined) {
    return null;
  }
  try {
    return javaByteArraySummary(hashObject.toByteArray(), 8);
  } catch (error) {
    return { length: null, prefixHex: '', sha256PrefixHex: null, error: String(error) };
  }
}

function readByteBuffer(buffer, maxBytes) {
  if (buffer === null || buffer === undefined) {
    return { length: 0, position: 0, limit: 0, captured: 0, complete: true, hex: '', sha256PrefixHex: null };
  }

  const duplicate = buffer.duplicate();
  const position = duplicate.position();
  const limit = duplicate.limit();
  const remaining = duplicate.remaining();
  let sha256 = null;
  try {
    const digestDuplicate = buffer.duplicate();
    digestDuplicate.position(position);
    digestDuplicate.limit(limit);
    const digestBytes = Java.array('byte', Array(remaining).fill(0));
    digestDuplicate.get(digestBytes);
    const MessageDigest = Java.use('java.security.MessageDigest');
    sha256 = byteArrayToHex(MessageDigest.getInstance('SHA-256').digest(digestBytes), 8);
  } catch (error) {
    sha256 = 'error:' + String(error);
  }
  const captureLength = Math.min(remaining, maxBytes || MAX_HEX_BYTES);
  const initial = [];
  for (let i = 0; i < captureLength; i += 1) {
    initial.push(0);
  }
  const bytes = Java.array('byte', initial);
  duplicate.get(bytes);
  return {
    length: remaining,
    position: position,
    limit: limit,
    captured: captureLength,
    complete: captureLength === remaining,
    sha256PrefixHex: sha256,
    hex: byteArrayToHex(bytes, captureLength)
  };
}

function readByteBufferWindow(buffer, start, length, maxBytes) {
  if (buffer === null || buffer === undefined || start === null || length === null || length <= 0) {
    return { length: 0, position: start || 0, limit: start || 0, captured: 0, complete: true, hex: '', sha256PrefixHex: null };
  }

  const duplicate = buffer.duplicate();
  const originalLimit = duplicate.limit();
  const safeStart = Math.max(0, Math.min(start, originalLimit));
  const safeEnd = Math.max(safeStart, Math.min(safeStart + length, originalLimit));
  const windowLength = safeEnd - safeStart;
  let sha256 = null;
  try {
    const digestDuplicate = buffer.duplicate();
    digestDuplicate.position(safeStart);
    digestDuplicate.limit(safeEnd);
    const digestBytes = Java.array('byte', Array(windowLength).fill(0));
    digestDuplicate.get(digestBytes);
    const MessageDigest = Java.use('java.security.MessageDigest');
    sha256 = byteArrayToHex(MessageDigest.getInstance('SHA-256').digest(digestBytes), 8);
  } catch (error) {
    sha256 = 'error:' + String(error);
  }
  const captureLength = Math.min(safeEnd - safeStart, maxBytes || MAX_HEX_BYTES);
  const initial = [];
  for (let i = 0; i < captureLength; i += 1) {
    initial.push(0);
  }
  const bytes = Java.array('byte', initial);
  duplicate.position(safeStart);
  duplicate.limit(safeStart + captureLength);
  duplicate.get(bytes);
  return {
    length: windowLength,
    position: safeStart,
    limit: safeEnd,
    captured: captureLength,
    complete: captureLength === windowLength,
    sha256PrefixHex: sha256,
    hex: byteArrayToHex(bytes, captureLength)
  };
}

function airShieldOuterFrameSummary(window) {
  const hex = window && window.hex ? String(window.hex).replace('...', '') : '';
  if (hex.length < 18) {
    return {
      length: window ? window.length : 0,
      captured: window ? window.captured : 0,
      complete: !!(window && window.complete),
      sha256PrefixHex: window ? window.sha256PrefixHex : null
    };
  }

  const indicator = parseInt(hex.slice(16, 18), 16);
  return {
    length: window.length,
    captured: window.captured,
    complete: !!window.complete,
    sha256PrefixHex: window.sha256PrefixHex,
    validationPrefixHex: hex.slice(0, 16),
    cipherPayloadIndicator: indicator,
    expectedOuterLength: indicator * 16 + 25,
    cipherPayloadCapturedHex: hex.slice(18)
  };
}

function typedBufferSummary(typedBuffer) {
  if (typedBuffer === null || typedBuffer === undefined) {
    return { type: null, size: 0, hex: '' };
  }

  let typeValue = null;
  let sizeValue = null;
  let bytesValue = null;
  try {
    typeValue = typedBuffer.type.value;
  } catch (_) {}
  try {
    sizeValue = typedBuffer.getSize();
  } catch (_) {}
  try {
    bytesValue = typedBuffer.bytes.value;
  } catch (_) {}

  const buffer = readByteBuffer(bytesValue);
  return {
    type: typeValue,
    size: sizeValue,
    bufferLength: buffer.length,
    position: buffer.position,
    limit: buffer.limit,
    hex: buffer.hex
  };
}

function hookIfPresent(className, installer) {
  try {
    const klass = Java.use(className);
    installer(klass);
    log('hook.installed', { className: className });
  } catch (error) {
    log('hook.missing', { className: className, error: String(error) });
  }
}

function fieldValue(instance, name) {
  try {
    const field = instance[name];
    if (field === null || field === undefined) {
      return null;
    }
    return field.value;
  } catch (_) {
    return null;
  }
}

function fieldPresent(instance, name) {
  return fieldValue(instance, name) !== null;
}

function authDelegateState(instance, className) {
  if (className === 'X.GD5') {
    return {
      retryAttempt: fieldValue(instance, 'A00'),
      hasIdentity: fieldPresent(instance, 'A02')
    };
  }

  if (className === 'X.GCS') {
    return {
      hasChallenges: fieldPresent(instance, 'A00'),
      hasConstellationAuth: fieldPresent(instance, 'A01'),
      tag: String(fieldValue(instance, 'A02'))
    };
  }

  if (className === 'X.C30908GCi') {
    return {
      prototypeRetryAttempt: fieldValue(instance, 'A02'),
      hasPrototypeIdentity: fieldPresent(instance, 'A00'),
      hasIdentityDelegate: fieldPresent(instance, 'A03')
    };
  }

  return {};
}

function installAuthDelegateTrace(className, delegateName) {
  hookIfPresent(className, function(AuthDelegate) {
    let a7kInstalled = 0;
    if (AuthDelegate.A7K) {
      AuthDelegate.A7K.overloads.forEach(function(overload) {
        if (overload.argumentTypes.length !== 4) {
          return;
        }
        a7kInstalled += 1;
        overload.implementation = function(progress, success, failure, allowOffload) {
          log('airshield.auth.delegate.start', Object.assign({
            className: className,
            delegate: delegateName,
            allowOffload: !!allowOffload
          }, authDelegateState(this, className)));
          return overload.call(this, progress, success, failure, allowOffload);
        };
      });
    }

    let registerInstalled = 0;
    if (AuthDelegate.BZa) {
      AuthDelegate.BZa.overloads.forEach(function(overload) {
        if (overload.argumentTypes.length !== 4) {
          return;
        }
        registerInstalled += 1;
        overload.implementation = function(looper, txChallenge, rxChallenge, connection) {
          log('airshield.auth.delegate.register_services', Object.assign({
            className: className,
            delegate: delegateName,
            txChallenge: airShieldHashSummary(txChallenge),
            rxChallenge: airShieldHashSummary(rxChallenge)
          }, authDelegateState(this, className)));
          return overload.call(this, looper, txChallenge, rxChallenge, connection);
        };
      });
    }

    log('airshield.auth.delegate.hooks', {
      className: className,
      delegate: delegateName,
      a7kOverloads: a7kInstalled,
      registerServiceOverloads: registerInstalled
    });
  });
}

function installCipherBuilderTrace() {
  hookIfPresent('com.facebook.wearable.airshield.stream.CipherBuilder', function(CipherBuilder) {
    [
      { method: 'buildTxChallenge', event: 'airshield.cipher_builder.build_tx_challenge', role: 'txChallenge' },
      { method: 'buildRxChallenge', event: 'airshield.cipher_builder.build_rx_challenge', role: 'rxChallenge' },
      { method: 'buildTxChallengeNative', event: 'airshield.cipher_builder.build_tx_challenge_native', role: 'txChallenge' },
      { method: 'buildRxChallengeNative', event: 'airshield.cipher_builder.build_rx_challenge_native', role: 'rxChallenge' }
    ].forEach(function(item) {
      if (!CipherBuilder[item.method]) {
        return;
      }
      try {
        const overload = CipherBuilder[item.method].overload();
        overload.implementation = function() {
          const result = overload.call(this);
          log(item.event, {
            role: item.role,
            challenge: airShieldHashSummary(result)
          });
          return result;
        };
      } catch (error) {
        log('airshield.cipher_builder.challenge_hook_failed', {
          method: item.method,
          error: String(error)
        });
      }
    });

    if (CipherBuilder.setChallenge) {
      try {
        const setChallenge = CipherBuilder.setChallenge.overload('[B');
        setChallenge.implementation = function(bytes) {
          log('airshield.cipher_builder.set_challenge', {
            challenge: javaByteArraySummary(bytes, 8),
            transcriptChallengeWindow: transcriptChallengeWindowSummary(bytes)
          });
          return setChallenge.call(this, bytes);
        };
      } catch (error) {
        log('airshield.cipher_builder.setter_hook_failed', {
          method: 'setChallenge',
          error: String(error)
        });
      }
    }

    if (CipherBuilder.setSeed) {
      try {
        const setSeed = CipherBuilder.setSeed.overload('[B');
        setSeed.implementation = function(bytes) {
          log('airshield.cipher_builder.set_seed', {
            seed: javaByteArraySummary(bytes, 8),
            transcriptMaterialWindow: transcriptMaterialWindowSummary(bytes)
          });
          return setSeed.call(this, bytes);
        };
      } catch (error) {
        log('airshield.cipher_builder.setter_hook_failed', {
          method: 'setSeed',
          error: String(error)
        });
      }
    }

    if (CipherBuilder.setRemotePublicKey) {
      try {
        const setRemotePublicKey = CipherBuilder.setRemotePublicKey.overload('com.facebook.wearable.airshield.security.PublicKey');
        setRemotePublicKey.implementation = function(publicKey) {
          let summary = null;
          try {
            summary = publicKey ? javaByteArraySummary(publicKey.serialize(), 8) : null;
          } catch (error) {
            summary = { length: null, prefixHex: '', sha256PrefixHex: null, error: String(error) };
          }
          log('airshield.cipher_builder.set_remote_public_key', {
            publicKey: summary
          });
          return setRemotePublicKey.call(this, publicKey);
        };
      } catch (error) {
        log('airshield.cipher_builder.setter_hook_failed', {
          method: 'setRemotePublicKey',
          error: String(error)
        });
      }
    }

    if (CipherBuilder.setInitializationVector) {
      try {
        const setInitializationVector = CipherBuilder.setInitializationVector.overload('com.facebook.wearable.airshield.security.InitializationVector');
        setInitializationVector.implementation = function(initializationVector) {
          let summary = null;
          try {
            summary = initializationVector ? javaByteArraySummary(initializationVector.toByteArray(), 8) : null;
          } catch (error) {
            summary = { length: null, prefixHex: '', sha256PrefixHex: null, error: String(error) };
          }
          log('airshield.cipher_builder.set_initialization_vector', {
            initializationVector: summary
          });
          return setInitializationVector.call(this, initializationVector);
        };
      } catch (error) {
        log('airshield.cipher_builder.setter_hook_failed', {
          method: 'setInitializationVector',
          error: String(error)
        });
      }
    }
  });
}

function pointerSummary(pointer) {
  if (pointer === null || pointer === undefined || pointer.isNull()) {
    return { pointer: '0x0' };
  }
  const module = Process.findModuleByAddress(pointer);
  if (!module) {
    return { pointer: String(pointer) };
  }
  return {
    pointer: String(pointer),
    module: module.name,
    moduleBase: String(module.base),
    moduleOffset: String(pointer.sub(module.base))
  };
}

function readCStringSafe(pointer) {
  try {
    if (pointer === null || pointer === undefined || pointer.isNull()) {
      return null;
    }
    return pointer.readCString();
  } catch (_) {
    return null;
  }
}

function bytesToHex(bytes) {
  if (!bytes) {
    return '';
  }
  const view = new Uint8Array(bytes);
  let hex = '';
  for (let i = 0; i < view.length; i += 1) {
    hex += ('0' + view[i].toString(16)).slice(-2);
  }
  return hex;
}

function readMemoryBytes(pointer, length) {
  try {
    if (pointer === null || pointer === undefined || pointer.isNull() || length <= 0) {
      return null;
    }
    return pointer.readByteArray(length);
  } catch (_) {
    return null;
  }
}

function sha256Prefix(bytes, prefixLength) {
  try {
    if (!bytes) {
      return null;
    }
    return Checksum.compute('sha256', bytes).slice(0, prefixLength || 16);
  } catch (_) {
    return null;
  }
}

function readMemoryFingerprint(pointer, length) {
  return sha256Prefix(readMemoryBytes(pointer, length), 16);
}

function safePointerLength(pointerValue) {
  try {
    const length = pointerValue.toUInt32();
    if (length > 4096) {
      return null;
    }
    return length;
  } catch (_) {
    return null;
  }
}

function readU8Safe(pointer, offset) {
  try {
    return pointer.add(offset).readU8();
  } catch (_) {
    return null;
  }
}

function readU16Safe(pointer, offset) {
  try {
    return pointer.add(offset).readU16();
  } catch (_) {
    return null;
  }
}

function readU32Safe(pointer, offset) {
  try {
    return pointer.add(offset).readU32();
  } catch (_) {
    return null;
  }
}

function pointerWordsFingerprint(lowWord, highWord) {
  try {
    const scratch = Memory.alloc(16);
    scratch.writePointer(lowWord);
    scratch.add(Process.pointerSize).writePointer(highWord);
    return readMemoryFingerprint(scratch, 16);
  } catch (_) {
    return null;
  }
}

function jclassName(env, jclass) {
  try {
    if (!env) {
      return null;
    }
    return env.getClassName(jclass);
  } catch (_) {
    return null;
  }
}

function nativeMethodIsInteresting(className, methodName) {
  const lowerClassName = (className || '').toLowerCase();
  if (lowerClassName.indexOf('airshield') !== -1) {
    return true;
  }
  return nativeInterestingNames.indexOf(methodName) !== -1;
}

function maybeLogNativeAirShieldState(methodName, args, fnPtr) {
  if (methodName.indexOf('rxFramingStateSetupHelper') !== -1) {
    const builder = args[1];
    log('native.airshield.state_setup_inputs', Object.assign({
      helper: methodName,
      builderPointer: String(builder),
      directionFlag: args[2].toInt32(),
      transcriptChallengeWindowFingerprint: readMemoryFingerprint(builder.add(0x108), 16),
      localNativeHashSourceFingerprint: readMemoryFingerprint(builder.add(0x118), 64),
      localNativeHashActiveFlag: readU8Safe(builder, 0x210),
      transcriptMaterialWindowFingerprint: readMemoryFingerprint(builder.add(0x218), 32),
      remotePublicKeyActiveFlag: readU8Safe(builder, 0x218),
      selectedCounterInputFingerprint: readMemoryFingerprint(builder.add(0x238), 16),
      rawChallengeFingerprint: readMemoryFingerprint(builder.add(0x110), 16),
      rawSeedFingerprint: readMemoryFingerprint(builder.add(0x220), 32),
      rawInitializationVectorFingerprint: readMemoryFingerprint(builder.add(0x240), 16)
    }, pointerSummary(fnPtr)));
  } else if (methodName.indexOf('framingKeyDerivationHelper') !== -1) {
    const keyMaterial = args[2];
    const contextPointer = args[3];
    const contextLength = safePointerLength(args[4]);
    const usesDefaultContext = contextPointer.isNull() || contextLength === null || contextLength === 0;
    log('native.airshield.framing_expansion', Object.assign({
      helper: methodName,
      outputPointer: String(args[0]),
      keyMaterialPointer: String(keyMaterial),
      keyMaterialFingerprint: readMemoryFingerprint(keyMaterial, 32),
      contextPointer: String(contextPointer),
      contextLength: usesDefaultContext ? 9 : contextLength,
      contextSource: usesDefaultContext ? 'default_airshield_label' : (contextLength === 0x88 ? 'explicit_airshield_context_0x88' : 'caller_context'),
      contextFingerprint: usesDefaultContext
        ? sha256Prefix(Memory.allocUtf8String('AirShield').readByteArray(9), 16)
        : readMemoryFingerprint(contextPointer, contextLength)
    }, pointerSummary(fnPtr)));
  } else if (methodName.indexOf('framingConfigCopyHelper') !== -1) {
    const config = args[1];
    const validationModeLow = readU16Safe(config, 0x78);
    const validationModeHigh = readU8Safe(config, 0x7a);
    const frameCounter = readU32Safe(config, 0x7c);
    const runtimeValidationMode = validationModeLow === null || validationModeHigh === null
      ? null
      : (validationModeLow | (validationModeHigh << 24)) >>> 0;
    log('native.airshield.framing_config', Object.assign({
      helper: methodName,
      configPointer: String(config),
      validationKeyFingerprint: readMemoryFingerprint(config, 32),
      validationModeLow16: validationModeLow,
      validationModeHigh8: validationModeHigh,
      runtimeValidationMode: runtimeValidationMode,
      frameCounter: frameCounter
    }, pointerSummary(fnPtr)));
  } else if (methodName.indexOf('cipherContextBuilderHelper') !== -1) {
    const keyMaterial = args[1];
    log('native.airshield.cipher_context_setup', Object.assign({
      helper: methodName,
      keyMaterialPointer: String(keyMaterial),
      cipherKeyFingerprint: readMemoryFingerprint(keyMaterial, 32),
      transformModeArg: args[2].toInt32(),
      initialCounterBlockFingerprint: pointerWordsFingerprint(args[3], args[4])
    }, pointerSummary(fnPtr)));
  }
}

function nativeAirShieldEnterState(methodName, args) {
  if (methodName.indexOf('framingKeyDerivationHelper') === -1) {
    return null;
  }
  return {
    kind: 'framing_expansion',
    outputPointer: args[0],
    keyMaterialPointer: args[2],
    contextPointer: args[3],
    contextLength: safePointerLength(args[4])
  };
}

function maybeLogNativeAirShieldLeaveState(methodName, enterState, retval, fnPtr) {
  if (!enterState || enterState.kind !== 'framing_expansion') {
    return;
  }
  const outputPointer = enterState.outputPointer;
  log('native.airshield.framing_expansion_output', Object.assign({
    helper: methodName,
    retval: String(retval),
    outputPointer: String(outputPointer),
    outputFingerprint: readMemoryFingerprint(outputPointer, 32),
    outputInlineTagU32: readU32Safe(outputPointer, 0x20),
    keyMaterialPointer: String(enterState.keyMaterialPointer),
    contextPointer: String(enterState.contextPointer),
    contextLength: enterState.contextLength
  }, pointerSummary(fnPtr)));
}

function installNativeMethodHook(className, methodName, signature, fnPtr, argStart) {
  const key = String(fnPtr) + ':' + methodName;
  if (nativeHookedPointers[key]) {
    return;
  }
  nativeHookedPointers[key] = true;
  const firstArg = argStart === undefined ? 2 : argStart;

  try {
    Interceptor.attach(fnPtr, {
      onEnter: function(args) {
        this.airShieldEnterState = nativeAirShieldEnterState(methodName, args);
        const argPointers = [];
        for (let i = firstArg; i < 8; i += 1) {
          try {
            argPointers.push(String(args[i]));
          } catch (_) {}
        }
        log('native.airshield.method.enter', Object.assign({
          className: className,
          methodName: methodName,
          signature: signature,
          args: argPointers
        }, pointerSummary(fnPtr)));
        maybeLogNativeAirShieldState(methodName, args, fnPtr);
      },
      onLeave: function(retval) {
        maybeLogNativeAirShieldLeaveState(methodName, this.airShieldEnterState, retval, fnPtr);
        log('native.airshield.method.leave', Object.assign({
          className: className,
          methodName: methodName,
          signature: signature,
          retval: String(retval)
        }, pointerSummary(fnPtr)));
      }
    });
    log('native.airshield.method.hookInstalled', Object.assign({
      className: className,
      methodName: methodName,
      signature: signature
    }, pointerSummary(fnPtr)));
  } catch (error) {
    log('native.airshield.method.hookFailed', Object.assign({
      className: className,
      methodName: methodName,
      signature: signature,
      error: String(error)
    }, pointerSummary(fnPtr)));
  }
}

function installStaticAirShieldMethodHooks() {
  const module = Process.findModuleByName('libstartup.so');
  if (!module) {
    return false;
  }

  let installedCount = 0;
  staticAirShieldMethods.forEach(function(method) {
    const pointer = module.base.add(method.offset);
    installNativeMethodHook(
      method.className,
      method.methodName + ':' + method.source,
      method.signature,
      pointer,
      method.argStart
    );
    installedCount += 1;
  });

  log('native.airshield.staticHooks.installed', {
    module: module.name,
    moduleBase: String(module.base),
    methodCount: installedCount
  });
  return true;
}

function scheduleStaticAirShieldMethodHooks() {
  if (installStaticAirShieldMethodHooks()) {
    return;
  }

  let attempts = 0;
  const timer = setInterval(function() {
    attempts += 1;
    if (installStaticAirShieldMethodHooks()) {
      clearInterval(timer);
      return;
    }
    if (attempts >= 30) {
      clearInterval(timer);
      log('native.airshield.staticHooks.moduleMissing', {
        module: 'libstartup.so',
        attempts: attempts
      });
    }
  }, 500);
}

function installRegisterNativesHooks() {
  let symbols = [];
  try {
    symbols = Process.getModuleByName('libart.so').enumerateSymbols();
  } catch (error) {
    log('native.registerNatives.moduleMissing', { error: String(error) });
    return;
  }

  const targets = symbols.filter(function(symbol) {
    return symbol.name.indexOf('RegisterNatives') !== -1
      && symbol.name.indexOf('CheckJNI') === -1
      && symbol.name.indexOf('art') !== -1;
  });
  const installed = {};

  targets.forEach(function(symbol) {
    const address = String(symbol.address);
    if (installed[address]) {
      return;
    }
    installed[address] = true;

    try {
      Interceptor.attach(symbol.address, {
        onEnter: function(args) {
          let env = null;
          try {
            env = Java.vm.tryGetEnv();
          } catch (_) {}
          const className = jclassName(env, args[1]);
          const methodCount = args[3].toInt32();
          const methodSize = Process.pointerSize * 3;
          const methods = [];

          for (let i = 0; i < methodCount; i += 1) {
            const entry = args[2].add(i * methodSize);
            const name = readCStringSafe(entry.readPointer());
            const signature = readCStringSafe(entry.add(Process.pointerSize).readPointer());
            const fnPtr = entry.add(Process.pointerSize * 2).readPointer();
            const summary = Object.assign({
              index: i,
              className: className,
              methodName: name,
              signature: signature
            }, pointerSummary(fnPtr));
            methods.push(summary);

            if (nativeMethodIsInteresting(className, name)) {
              log('native.registerNatives.airshieldMethod', summary);
              installNativeMethodHook(className, name, signature, fnPtr);
            }
          }

          if ((className || '').toLowerCase().indexOf('airshield') !== -1) {
            log('native.registerNatives.airshieldClass', {
              symbol: symbol.name,
              className: className,
              methodCount: methodCount,
              methods: methods
            });
          }
        }
      });
      log('native.registerNatives.hookInstalled', {
        symbol: symbol.name,
        address: String(symbol.address)
      });
    } catch (error) {
      log('native.registerNatives.hookFailed', {
        symbol: symbol.name,
        address: String(symbol.address),
        error: String(error)
      });
    }
  });

  log('native.registerNatives.hookSummary', {
    candidateCount: targets.length,
    installedCount: Object.keys(installed).length
  });
}

function installHooks() {
  hookIfPresent('android.bluetooth.BluetoothDevice', function(BluetoothDevice) {
    BluetoothDevice.createInsecureL2capChannel.overload('int').implementation = function(psm) {
      log('ble.createInsecureL2capChannel', {
        name: this.getName(),
        address: this.getAddress(),
        psm: psm
      });
      return this.createInsecureL2capChannel(psm);
    };
    BluetoothDevice.createL2capChannel.overload('int').implementation = function(psm) {
      log('ble.createL2capChannel', {
        name: this.getName(),
        address: this.getAddress(),
        psm: psm
      });
      return this.createL2capChannel(psm);
    };
  });

  hookIfPresent('android.bluetooth.BluetoothSocket', function(BluetoothSocket) {
    BluetoothSocket.connect.implementation = function() {
      log('ble.socket.connect.begin', {});
      const result = this.connect();
      log('ble.socket.connect.end', {});
      return result;
    };
    BluetoothSocket.getInputStream.implementation = function() {
      log('ble.socket.getInputStream', {});
      return this.getInputStream();
    };
    BluetoothSocket.getOutputStream.implementation = function() {
      log('ble.socket.getOutputStream', {});
      return this.getOutputStream();
    };
  });

  hookIfPresent('com.facebook.wearable.airshield.securer.StreamSecurerImpl', function(StreamSecurerImpl) {
    StreamSecurerImpl.initialize.overload('boolean', 'boolean', 'boolean').implementation = function(a, b, c) {
      log('airshield.initialize', {
        arg0: a,
        arg1: b,
        arg2: c
      });
      return this.initialize(a, b, c);
    };

    StreamSecurerImpl.start.implementation = function() {
      log('airshield.start', {});
      return this.start();
    };

    StreamSecurerImpl.receiveData.overload('java.nio.ByteBuffer').implementation = function(buffer) {
      log('airshield.receiveData', readByteBuffer(buffer));
      return this.receiveData(buffer);
    };

    StreamSecurerImpl.receiveSingleFrame.overload('java.nio.ByteBuffer').implementation = function(buffer) {
      log('airshield.receiveSingleFrame', readByteBuffer(buffer));
      return this.receiveSingleFrame(buffer);
    };

    StreamSecurerImpl.handleSend.overload('java.nio.ByteBuffer').implementation = function(buffer) {
      log('airshield.onSend', readByteBuffer(buffer));
      return this.handleSend(buffer);
    };

    StreamSecurerImpl.handlePreambleReady.overload('com.facebook.wearable.airshield.securer.Preamble').implementation = function(preamble) {
      let streamId = null;
      let encrypted = null;
      try {
        streamId = preamble.getStreamId();
      } catch (_) {}
      try {
        encrypted = preamble.isEncrypted();
      } catch (_) {}
      log('airshield.preambleReady', {
        streamId: streamId,
        encrypted: encrypted
      });
      return this.handlePreambleReady(preamble);
    };

    StreamSecurerImpl.handleStreamReady.overload('long', '[B').implementation = function(handle, rollover) {
      log('airshield.streamReady', {
        handle: String(handle),
        rolloverLength: rollover ? rollover.length : 0,
        rolloverHex: rollover ? byteArrayToHex(rollover, MAX_HEX_BYTES) : ''
      });
      return this.handleStreamReady(handle, rollover);
    };
  });

  hookIfPresent('com.facebook.wearable.airshield.securer.Preamble', function(Preamble) {
    const getTxChallenge = Preamble.getTxChallenge.overload();
    getTxChallenge.implementation = function() {
      const result = getTxChallenge.call(this);
      log('airshield.preamble.getTxChallenge', {
        role: 'txChallenge',
        challenge: airShieldHashSummary(result)
      });
      return result;
    };
    const getRxChallenge = Preamble.getRxChallenge.overload();
    getRxChallenge.implementation = function() {
      const result = getRxChallenge.call(this);
      log('airshield.preamble.getRxChallenge', {
        role: 'rxChallenge',
        challenge: airShieldHashSummary(result)
      });
      return result;
    };
    const getConnection = Preamble.getConnection.overload();
    getConnection.implementation = function() {
      const result = getConnection.call(this);
      log('airshield.preamble.getConnection', {});
      return result;
    };
    Preamble.acceptAuthentication.overload('[B', 'kotlin.jvm.functions.Function1').implementation = function(pubKey, callback) {
      const publicKey = javaByteArraySummary(pubKey, 8);
      log('airshield.acceptAuthentication', {
        publicKey: publicKey,
        pubKeyLength: publicKey.length,
        pubKeyFingerprint: publicKey.sha256PrefixHex
      });
      return this.acceptAuthentication(pubKey, callback);
    };
    Preamble.rejectAuthentication.overload('int').implementation = function(code) {
      log('airshield.rejectAuthentication', { code: code });
      return this.rejectAuthentication(code);
    };
  });

  installAuthDelegateTrace('X.GD5', 'IdentityAuthenticationDelegate');
  installAuthDelegateTrace('X.GCS', 'ACDCAuthenticationDelegate');
  installAuthDelegateTrace('X.C30908GCi', 'IdentityAndPrototypeAuthenticationDelegate');
  installCipherBuilderTrace();

  hookIfPresent('com.facebook.wearable.airshield.security.PrivateKey', function(PrivateKey) {
    if (PrivateKey.derive) {
      const derive = PrivateKey.derive.overload('com.facebook.wearable.airshield.security.PublicKey');
      derive.implementation = function(publicKey) {
        let publicKeySummary = null;
        try {
          publicKeySummary = publicKey ? javaByteArraySummary(publicKey.serialize(), 8) : null;
        } catch (error) {
          publicKeySummary = { length: null, prefixHex: '', sha256PrefixHex: null, error: String(error) };
        }
        const result = derive.call(this, publicKey);
        log('airshield.identity.private_key.derive', {
          publicKey: publicKeySummary,
          sharedHash: airShieldHashSummary(result)
        });
        return result;
      };
    }
    if (PrivateKey.setRaw) {
      PrivateKey.setRaw.overload('[B').implementation = function(bytes) {
        log('airshield.identity.private_key.set_raw', {
          rawPrivateKey: javaByteArraySummary(bytes, 8)
        });
        return this.setRaw(bytes);
      };
    }
    if (PrivateKey.serialize) {
      PrivateKey.serialize.implementation = function() {
        const result = this.serialize();
        log('airshield.identity.private_key.serialize', {
          rawPrivateKey: javaByteArraySummary(result, 8)
        });
        return result;
      };
    }
    if (PrivateKey.recoverPublicKey) {
      PrivateKey.recoverPublicKey.implementation = function() {
        const result = this.recoverPublicKey();
        let publicKey = null;
        try {
          publicKey = result ? javaByteArraySummary(result.serialize(), 8) : null;
        } catch (error) {
          publicKey = { error: String(error) };
        }
        log('airshield.identity.private_key.recover_public_key', {
          publicKey: publicKey
        });
        return result;
      };
    }
  });

  hookIfPresent('com.facebook.wearable.airshield.security.PublicKey', function(PublicKey) {
    if (PublicKey.setRaw) {
      PublicKey.setRaw.overload('[B').implementation = function(bytes) {
        log('airshield.identity.public_key.set_raw', {
          publicKey: javaByteArraySummary(bytes, 8)
        });
        return this.setRaw(bytes);
      };
    }
    if (PublicKey.serialize) {
      PublicKey.serialize.implementation = function() {
        const result = this.serialize();
        log('airshield.identity.public_key.serialize', {
          publicKey: javaByteArraySummary(result, 8)
        });
        return result;
      };
    }
  });

  hookIfPresent('X.G44', function(G44) {
    const invokeObject = G44.invoke.overload('java.lang.Object');
    invokeObject.implementation = function(obj) {
      const variant = fieldValue(this, '$t');
      const publicKey = javaByteArraySummary(obj, 8);
      if (publicKey.length !== null && variant !== 0 && variant !== 1) {
        log('airshield.auth.accept_key_candidate', {
          className: 'X.G44',
          variant: variant,
          asMain: !!fieldValue(this, 'A02'),
          originalPublicKey: publicKey,
          paddedPublicKeyLength: 64
        });
      }
      return invokeObject.call(this, obj);
    };
  });

  hookIfPresent('X.GY7', function(GY7) {
    const invokeObject = GY7.invoke.overload('java.lang.Object');
    invokeObject.implementation = function(obj) {
      const variant = fieldValue(this, '$t');
      if (variant === 0 || variant === 1) {
        const publicKey = javaByteArraySummary(fieldValue(this, 'A03'), 8);
        log('airshield.auth.result_callback', {
          className: 'X.GY7',
          variant: variant,
          path: variant === 0 ? 'identityRetry' : 'acdcResult',
          allowOffload: !!fieldValue(this, 'A05'),
          carriedPublicKey: publicKey.length === null ? null : publicKey
        });
      }
      return invokeObject.call(this, obj);
    };
  });

  hookIfPresent('com.facebook.wearable.airshield.securer.EndLinkSetupMessage', function(EndLinkSetupMessage) {
    EndLinkSetupMessage.setAsMain.overload('boolean').implementation = function(asMain) {
      log('airshield.endLinkSetup.setAsMain', { asMain: asMain });
      return this.setAsMain(asMain);
    };
    EndLinkSetupMessage.setUserData.overload('short', '[B').implementation = function(tag, bytes) {
      log('airshield.endLinkSetup.setUserData', {
        tag: tag,
        userData: javaByteArraySummary(bytes, 8)
      });
      return this.setUserData(tag, bytes);
    };
  });

  hookIfPresent('com.facebook.wearable.airshield.stream.Framing', function(Framing) {
    Framing.pack.overload('java.nio.ByteBuffer', 'java.nio.ByteBuffer').implementation = function(plainBuffer, outerBuffer) {
      const plainBeforePosition = plainBuffer.position();
      const plainBeforeRemaining = plainBuffer.remaining();
      const outerBeforePosition = outerBuffer.position();
      const outerBeforeRemaining = outerBuffer.remaining();
      const plainBefore = readByteBufferWindow(plainBuffer, plainBeforePosition, plainBeforeRemaining);
      const result = this.pack(plainBuffer, outerBuffer);
      const plainAfterPosition = plainBuffer.position();
      const outerAfterPosition = outerBuffer.position();
      const plainConsumed = Math.max(0, plainAfterPosition - plainBeforePosition);
      const outerWritten = Math.max(0, outerAfterPosition - outerBeforePosition);
      const outerAfter = readByteBufferWindow(outerBuffer, outerBeforePosition, outerWritten);
      log('airshield.framing.pack', {
        result: String(result),
        plainBeforePosition: plainBeforePosition,
        plainBeforeRemaining: plainBeforeRemaining,
        plainAfterPosition: plainAfterPosition,
        plainConsumed: plainConsumed,
        outerBeforePosition: outerBeforePosition,
        outerBeforeRemaining: outerBeforeRemaining,
        outerAfterPosition: outerAfterPosition,
        outerWritten: outerWritten,
        plaintext: plainBefore,
        outerFrame: outerAfter,
        outerFrameSummary: airShieldOuterFrameSummary(outerAfter)
      });
      return result;
    };

    Framing.unpack.overload('java.nio.ByteBuffer', 'java.nio.ByteBuffer').implementation = function(outerBuffer, plainBuffer) {
      const outerBeforePosition = outerBuffer.position();
      const outerBeforeRemaining = outerBuffer.remaining();
      const plainBeforePosition = plainBuffer.position();
      const plainBeforeRemaining = plainBuffer.remaining();
      const outerBefore = readByteBufferWindow(outerBuffer, outerBeforePosition, outerBeforeRemaining);
      const result = this.unpack(outerBuffer, plainBuffer);
      const outerAfterPosition = outerBuffer.position();
      const plainAfterPosition = plainBuffer.position();
      const outerConsumed = Math.max(0, outerAfterPosition - outerBeforePosition);
      const plainWritten = Math.max(0, plainAfterPosition - plainBeforePosition);
      const plainAfter = readByteBufferWindow(plainBuffer, plainBeforePosition, plainWritten);
      log('airshield.framing.unpack', {
        result: String(result),
        outerBeforePosition: outerBeforePosition,
        outerBeforeRemaining: outerBeforeRemaining,
        outerAfterPosition: outerAfterPosition,
        outerConsumed: outerConsumed,
        plainBeforePosition: plainBeforePosition,
        plainBeforeRemaining: plainBeforeRemaining,
        plainAfterPosition: plainAfterPosition,
        plainWritten: plainWritten,
        outerFrame: outerBefore,
        outerFrameSummary: airShieldOuterFrameSummary(outerBefore),
        plaintext: plainAfter
      });
      return result;
    };
  });

  hookIfPresent('com.facebook.wearable.datax.Connection', function(Connection) {
    Connection.openChannel.overload('int').implementation = function(service) {
      log('datax.openChannel', { service: service });
      return this.openChannel(service);
    };
    Connection.register.overload('com.facebook.wearable.datax.Service').implementation = function(service) {
      let serviceID = null;
      try {
        serviceID = service.getId();
      } catch (_) {}
      log('datax.registerService', { serviceID: serviceID });
      return this.register(service);
    };
    Connection.onReceived.overload('java.nio.ByteBuffer').implementation = function(buffer) {
      log('datax.onReceived', readByteBuffer(buffer));
      return this.onReceived(buffer);
    };
    Connection.onReceivedWithInterrupt.overload('java.nio.ByteBuffer').implementation = function(buffer) {
      log('datax.onReceivedWithInterrupt', readByteBuffer(buffer));
      return this.onReceivedWithInterrupt(buffer);
    };
    Connection.handleWrite.overload('java.nio.ByteBuffer', 'java.nio.ByteBuffer').implementation = function(header, payload) {
      log('datax.handleWrite', {
        header: readByteBuffer(header),
        payload: readByteBuffer(payload)
      });
      return this.handleWrite(header, payload);
    };
  });

  hookIfPresent('com.facebook.wearable.datax.LocalChannel', function(LocalChannel) {
    LocalChannel.$init.overload('com.facebook.wearable.datax.Connection', 'int', 'int', 'int').implementation = function(connection, service, qosPriority, qosTag) {
      const result = this.$init(connection, service, qosPriority, qosTag);
      const fields = {
        service: service,
        qosPriority: qosPriority,
        qosTag: qosTag
      };
      try {
        fields.channelId = this.getId();
      } catch (_) {}
      log('datax.localChannel.init', fields);
      return result;
    };
    LocalChannel.send.overload('com.facebook.wearable.datax.TypedBuffer').implementation = function(typedBuffer) {
      const summary = typedBufferSummary(typedBuffer);
      try {
        summary.channelId = this.getId();
      } catch (_) {}
      try {
        summary.service = this.getService();
      } catch (_) {}
      log('datax.localChannel.send', summary);
      return this.send(typedBuffer);
    };
  });

  hookIfPresent('com.facebook.wearable.datax.RemoteChannel', function(RemoteChannel) {
    RemoteChannel.send.overload('com.facebook.wearable.datax.TypedBuffer').implementation = function(typedBuffer) {
      const summary = typedBufferSummary(typedBuffer);
      try {
        summary.channelId = this.getId();
      } catch (_) {}
      try {
        summary.service = this.getService();
      } catch (_) {}
      log('datax.remoteChannel.send', summary);
      return this.send(typedBuffer);
    };
  });

  hookIfPresent('com.facebook.wearable.datax.TypedBuffer', function(TypedBuffer) {
    TypedBuffer.$init.overload('int', 'java.nio.ByteBuffer').implementation = function(type, bytes) {
      log('datax.typedBuffer.initByteBuffer', {
        type: type,
        bytes: readByteBuffer(bytes)
      });
      return this.$init(type, bytes);
    };
    TypedBuffer.$init.overload('int', '[B').implementation = function(type, bytes) {
      log('datax.typedBuffer.initByteArray', {
        type: type,
        length: bytes ? bytes.length : 0,
        hex: bytes ? byteArrayToHex(bytes, MAX_HEX_BYTES) : ''
      });
      return this.$init(type, bytes);
    };
  });
}

installRegisterNativesHooks();
scheduleStaticAirShieldMethodHooks();

Java.perform(function() {
  log('trace.ready', {
    maxHexBytes: MAX_HEX_BYTES
  });
  installHooks();
});
