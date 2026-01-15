import { uint8ArrayToBase64, base64ToUint8Array } from '.';
import { PublicKeys, PublicKeysBase64 } from '../types';
import { exportPublicKey, importPublicKey } from '../asymmetric-crypto';

/**
 * Converts a base64 string into PublicKeys type.
 *
 * @param base64 - The base64 representation of the public key.
 * @returns The resulting PublicKeys.
 */
export async function base64ToPublicKey(base64: PublicKeysBase64): Promise<PublicKeys> {
  try {
    const eccPublicKeyBytes = base64ToUint8Array(base64.eccPublicKeyBase64);
    const eccPublicKey = await importPublicKey(eccPublicKeyBytes);
    const kyberPublicKey = base64ToUint8Array(base64.kyberPublicKeyBase64);
    return {
      eccPublicKey: eccPublicKey,
      kyberPublicKey: kyberPublicKey,
    };
  } catch (error) {
    throw new Error('Failed to convert base64 to PublicKeys', { cause: error });
  }
}

/**
 * Converts a PublicKeys type into PublicKeysBase64.
 *
 * @param key - The PublicKeys key.
 * @returns The resulting PublicKeysBase64.
 */
export async function publicKeyToBase64(key: PublicKeys): Promise<PublicKeysBase64> {
  try {
    const eccPublicKeyArray = await exportPublicKey(key.eccPublicKey);
    const keys = {
      eccPublicKeyBase64: uint8ArrayToBase64(eccPublicKeyArray),
      kyberPublicKeyBase64: uint8ArrayToBase64(key.kyberPublicKey),
    };
    return keys;
  } catch (error) {
    throw new Error('Failed to convert key of the type PublicKeys to PublicKeysBase64', { cause: error });
  }
}
