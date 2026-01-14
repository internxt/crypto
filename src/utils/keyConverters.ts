import { uint8ArrayToBase64, base64ToUint8Array } from '.';
import { EmailKeys, EncryptedKeystore, PublicKeys } from '../types';
import { exportPublicKey, exportPrivateKey, importPublicKey, importPrivateKey } from '../asymmetric-crypto';

/**
 * Converts encryption keys to base64
 *
 * @param keys - The encryption keys
 * @returns The resulting base64 string
 */
export async function emailKeysToBase64(keys: EmailKeys): Promise<string> {
  try {
    const pkArray = await exportPublicKey(keys.userPublicKey);
    const skArray = await exportPrivateKey(keys.userPrivateKey);
    const json = JSON.stringify({
      userPublicKey: uint8ArrayToBase64(pkArray),
      userPrivateKey: uint8ArrayToBase64(skArray),
      userPublicKyberKey: uint8ArrayToBase64(keys.userPublicKyberKey),
      userPrivateKyberKey: uint8ArrayToBase64(keys.userPrivateKyberKey),
    });
    const base64 = btoa(json);
    return base64;
  } catch (error) {
    throw new Error('Failed to convert identity keys to base64', { cause: error });
  }
}

/**
 * Converts encrypted keystore to base64
 *
 * @param keystore - The encrypted keystore
 * @returns The resulting base64 string
 */
export function encryptedKeystoreToBase64(keystore: EncryptedKeystore): string {
  try {
    const ciphertext = uint8ArrayToBase64(keystore.encryptedKeys);
    const json = JSON.stringify({
      userEmail: keystore.userEmail,
      type: keystore.type.toString(),
      encryptedKeys: ciphertext,
    });
    const base64 = btoa(json);
    return base64;
  } catch (error) {
    throw new Error('Failed to convert encrypted keystore to base64', { cause: error });
  }
}

/**
 * Converts base64 to email keys
 *
 * @param base64 - The base64 input
 * @returns The resulting email keys
 */
export async function base64ToEmailKeys(base64: string): Promise<EmailKeys> {
  try {
    const json = atob(base64);
    const obj = JSON.parse(json);
    const pkArray = base64ToUint8Array(obj.userPublicKey);
    const skArray = base64ToUint8Array(obj.userPrivateKey);
    const pkCryptoKey = await importPublicKey(pkArray);
    const skCryptoKey = await importPrivateKey(skArray);
    const pkKyber = base64ToUint8Array(obj.userPublicKyberKey);
    const skKyber = base64ToUint8Array(obj.userPrivateKyberKey);
    const result: EmailKeys = {
      userPublicKey: pkCryptoKey,
      userPrivateKey: skCryptoKey,
      userPublicKyberKey: pkKyber,
      userPrivateKyberKey: skKyber,
    };
    return result;
  } catch (error) {
    throw new Error('Failed to convert base64 to encryption key', { cause: error });
  }
}

/**
 * Converts base64 to encrypted keystore
 *
 * @param base64 - The base64 input
 * @returns The resulting encrypted keystore
 */
export function base64ToEncryptedKeystore(base64: string): EncryptedKeystore {
  try {
    const json = atob(base64);
    const obj = JSON.parse(json);
    const ciphertext = base64ToUint8Array(obj.encryptedKeys);
    const result: EncryptedKeystore = {
      userEmail: obj.userEmail,
      type: obj.type,
      encryptedKeys: ciphertext,
    };
    return result;
  } catch (error) {
    throw new Error('Failed to convert base64 to encrypted keystore', { cause: error });
  }
}

/**
 * Converts a base64 string into PublicKeys type.
 *
 * @param base64 - The base64 representation of the public key.
 * @returns The resulting PublicKeys.
 */
export async function base64ToPublicKey(base64: string): Promise<PublicKeys> {
  try {
    const json = atob(base64);
    const obj = JSON.parse(json);
    const eccPublicKeyBytes = base64ToUint8Array(obj.eccPublicKey);
    const eccPublicKey = await importPublicKey(eccPublicKeyBytes);
    const kyberPublicKey = base64ToUint8Array(obj.kyberPublicKey);
    return {
      eccPublicKey: eccPublicKey,
      kyberPublicKey: kyberPublicKey,
    };
  } catch (error) {
    throw new Error('Failed to convert base64 to PublicKeys', { cause: error });
  }
}

/**
 * Converts a PublicKeys type into base64 string.
 *
 * @param key - The PublicKeys key.
 * @returns The resulting base64 string.
 */
export async function publicKeyToBase64(key: PublicKeys): Promise<string> {
  try {
    const eccPublicKeyArray = await exportPublicKey(key.eccPublicKey);
    const json = JSON.stringify({
      eccPublicKey: uint8ArrayToBase64(eccPublicKeyArray),
      kyberPublicKey: uint8ArrayToBase64(key.kyberPublicKey),
    });
    const base64 = btoa(json);
    return base64;
  } catch (error) {
    throw new Error('Failed to convert key of the type PublicKeys to base64', { cause: error });
  }
}
