import { IdentityKeys, EncryptionKeys, EncryptedKeystore } from '../utils/types';
import { uint8ArrayToBase64, base64ToUint8Array, decodeBase64 } from '../utils/converters';
import { exportPublicKey, exportPrivateKey, importPublicKey, importPrivateKey } from '../asymmetric-crypto/keys';
import { base64ToCiphertext, ciphertextToBase64 } from '../symmetric-crypto/utils';

/**
 * Converts identity keys to base64
 * @param keys - The identity keys
 * @returns The resulting base64 string
 */
export async function identityKeysToBase64(keys: IdentityKeys): Promise<string> {
  try {
    const pkArray = await exportPublicKey(keys.userPublicKey);
    const skArray = await exportPrivateKey(keys.userPrivateKey);
    const json = JSON.stringify({
      userPublicKey: uint8ArrayToBase64(pkArray),
      userPrivateKey: uint8ArrayToBase64(skArray),
    });
    const base64 = btoa(json);
    return base64;
  } catch (error) {
    throw new Error(`Cannot convert identity keys to base64: ${error}`);
  }
}

/**
 * Converts encryption keys to base64
 * @param keys - The encryption keys
 * @returns The resulting base64 string
 */
export async function encryptionKeysToBase64(keys: EncryptionKeys): Promise<string> {
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
    throw new Error(`Cannot convert identity keys to base64: ${error}`);
  }
}

/**
 * Converts encrypted keystore to base64
 * @param keystore - The encrypted keystore
 * @returns The resulting base64 string
 */
export function encryptedKeystoreToBase64(keystore: EncryptedKeystore): string {
  try {
    const ciphertext = ciphertextToBase64(keystore.encryptedKeys);
    const json = JSON.stringify({
      userID: keystore.userID,
      type: keystore.type.toString(),
      encryptedKeys: ciphertext,
    });
    const base64 = btoa(json);
    return base64;
  } catch (error) {
    throw new Error(`Cannot convert encrypted keystore to base64: ${error}`);
  }
}

/**
 * Converts base64 to identity keys
 * @param base64 - The base64 input
 * @returns The resulting idenity keys
 */
export async function base64ToIdentityKeys(base64: string): Promise<IdentityKeys> {
  try {
    const json = decodeBase64(base64);
    const obj = JSON.parse(json);
    const pkArray = base64ToUint8Array(obj.userPublicKey);
    const skArray = base64ToUint8Array(obj.userPrivateKey);
    const pkCryptoKey = await importPublicKey(pkArray);
    const skCryptoKey = await importPrivateKey(skArray);
    const result: IdentityKeys = {
      userPublicKey: pkCryptoKey,
      userPrivateKey: skCryptoKey,
    };
    return result;
  } catch (error) {
    throw new Error(`Cannot convert base64 to idenity key: ${error}`);
  }
}

/**
 * Converts base64 to encryption keys
 * @param base64 - The base64 input
 * @returns The resulting encryption keys
 */
export async function base64ToEncryptionKeys(base64: string): Promise<EncryptionKeys> {
  try {
    const json = decodeBase64(base64);
    const obj = JSON.parse(json);
    const pkArray = base64ToUint8Array(obj.userPublicKey);
    const skArray = base64ToUint8Array(obj.userPrivateKey);
    const pkCryptoKey = await importPublicKey(pkArray);
    const skCryptoKey = await importPrivateKey(skArray);
    const pkKyber = base64ToUint8Array(obj.userPublicKyberKey);
    const skKyber = base64ToUint8Array(obj.userPrivateKyberKey);
    const result: EncryptionKeys = {
      userPublicKey: pkCryptoKey,
      userPrivateKey: skCryptoKey,
      userPublicKyberKey: pkKyber,
      userPrivateKyberKey: skKyber,
    };
    return result;
  } catch (error) {
    throw new Error(`Cannot convert base64 to encryption key: ${error}`);
  }
}

/**
 * Converts base64 to encrypted keystore
 * @param base64 - The base64 input
 * @returns The resulting encrypted keystore
 */
export function base64ToEncryptedKeystore(base64: string): EncryptedKeystore {
  try {
    const json = decodeBase64(base64);
    const obj = JSON.parse(json);
    const ciphertext = base64ToCiphertext(obj.encryptedKeys);
    const result: EncryptedKeystore = {
      userID: obj.userID,
      type: obj.type,
      encryptedKeys: ciphertext,
    };
    return result;
  } catch (error) {
    throw new Error(`Cannot convert base64 to encrypted keystore: ${error}`);
  }
}
