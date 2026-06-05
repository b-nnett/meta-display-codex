'use strict';

function byteArrayToHex(bytes, maxBytes) {
  if (!bytes) {
    return '';
  }
  const length = Math.min(bytes.length, maxBytes || bytes.length);
  const parts = [];
  for (let index = 0; index < length; index++) {
    const value = bytes[index] & 0xff;
    parts.push(('0' + value.toString(16)).slice(-2));
  }
  return parts.join('');
}

function javaByteArraySummary(bytes, maxPrefixBytes) {
  if (!bytes) {
    return { length: null, prefixHex: '', sha256PrefixHex: null };
  }
  try {
    const MessageDigest = Java.use('java.security.MessageDigest');
    const digest = MessageDigest.getInstance('SHA-256');
    return {
      length: bytes.length,
      prefixHex: byteArrayToHex(bytes, maxPrefixBytes || 8),
      sha256PrefixHex: byteArrayToHex(digest.digest(bytes), 8)
    };
  } catch (error) {
    return {
      length: bytes.length,
      prefixHex: byteArrayToHex(bytes, maxPrefixBytes || 8),
      sha256PrefixHex: null,
      error: String(error)
    };
  }
}

function normalizeAcceptedAuthPublicKey(publicKeyBytes) {
  const normalized = [];
  const sourceLength = publicKeyBytes ? publicKeyBytes.length : 0;
  for (let index = 0; index < 64; index++) {
    normalized.push(index < sourceLength ? publicKeyBytes[index] : 0);
  }
  return Java.array('byte', normalized);
}

rpc.exports = {
  probe: function(base64Value) {
    let result = null;
    Java.perform(function() {
      const Base64 = Java.use('android.util.Base64');
      const PrivateKey = Java.use('com.facebook.wearable.airshield.security.PrivateKey');
      const raw = Base64.decode(String(base64Value).trim(), 2);

      result = {
        schema: 'codex_airshield_private_key_probe_v1',
        inputRawPrivateKey: javaByteArraySummary(raw, 8),
        nativeSetRawSucceeded: false,
        nativeSerialize: null,
        nativeRecoverPublicKey: null,
        acceptedAuthenticationPublicKey: null,
        errors: []
      };

      try {
        const privateKey = PrivateKey.$new();
        privateKey.setRaw(raw);
        result.nativeSetRawSucceeded = true;

        try {
          const serialized = privateKey.serialize();
          result.nativeSerialize = javaByteArraySummary(serialized, 8);
        } catch (serializeError) {
          result.errors.push({ step: 'private_key.serialize', error: String(serializeError) });
        }

        try {
          const publicKey = privateKey.recoverPublicKey();
          if (publicKey) {
            const publicSerialized = publicKey.serialize();
            result.nativeRecoverPublicKey = javaByteArraySummary(publicSerialized, 8);
            result.acceptedAuthenticationPublicKey = javaByteArraySummary(
              normalizeAcceptedAuthPublicKey(publicSerialized),
              8
            );
          }
        } catch (recoverError) {
          result.errors.push({ step: 'private_key.recover_public_key', error: String(recoverError) });
        }
      } catch (setRawError) {
        result.errors.push({ step: 'private_key.set_raw', error: String(setRawError) });
      }
    });
    return result;
  }
};
