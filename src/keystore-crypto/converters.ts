import {
  IdentityKeys,
  EncryptionKeys,
  EncryptedKeystore,
  uint8ArrayToBase64,
  base64ToUint8Array,
  SearchIndices,
} from '../utils';
import { exportPublicKey, exportPrivateKey, importPublicKey, importPrivateKey } from '../asymmetric-crypto';
import { base64ToCiphertext, ciphertextToBase64 } from '../symmetric-crypto';

/**
 * Converts identity keys to base64
 *
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
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to convert identity keys to base64: ${errorMessage}`);
  }
}

/**
 * Converts encryption keys to base64
 *
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
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to convert identity keys to base64: ${errorMessage}`);
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
    const ciphertext = ciphertextToBase64(keystore.encryptedKeys);
    const json = JSON.stringify({
      userID: keystore.userID,
      type: keystore.type.toString(),
      encryptedKeys: ciphertext,
    });
    const base64 = btoa(json);
    return base64;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to convert encrypted keystore to base64: ${errorMessage}`);
  }
}

/**
 * Converts base64 to identity keys
 *
 * @param base64 - The base64 input
 * @returns The resulting idenity keys
 */
export async function base64ToIdentityKeys(base64: string): Promise<IdentityKeys> {
  try {
    const json = atob(base64);
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
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed convert base64 to idenity key: ${errorMessage}`);
  }
}

/**
 * Converts base64 to encryption keys
 *
 * @param base64 - The base64 input
 * @returns The resulting encryption keys
 */
export async function base64ToEncryptionKeys(base64: string): Promise<EncryptionKeys> {
  try {
    const json = atob(base64);
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
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to convert base64 to encryption key: ${errorMessage}`);
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
    const ciphertext = base64ToCiphertext(obj.encryptedKeys);
    const result: EncryptedKeystore = {
      userID: obj.userID,
      type: obj.type,
      encryptedKeys: ciphertext,
    };
    return result;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to convert base64 to encrypted keystore: ${errorMessage}`);
  }
}

/**
 * Converts search indices to base64
 *
 * @param indices - The search indices
 * @returns The resulting base64 string
 */
export function searchIndicesToBase64(incides: SearchIndices): string {
  try {
    const content = uint8ArrayToBase64(incides.data);
    const time = btoa(incides.timestamp.getTime().toString());
    const json = JSON.stringify({
      userID: incides.userID,
      data: content,
      timestamp: time,
    });
    const base64 = btoa(json);
    return base64;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to convert search indices to base64: ${errorMessage}`);
  }
}

/**
 * Converts base64 to search indices
 *
 * @param base64 - The base64 input
 * @returns The resulting search indices
 */
export function base64ToSearchIndices(base64: string): SearchIndices {
  try {
    const json = atob(base64);
    const obj = JSON.parse(json);
    const content = base64ToUint8Array(obj.data);
    const time = atob(obj.timestamp);
    const result: SearchIndices = {
      userID: obj.userID,
      data: content,
      timestamp: new Date(parseInt(time, 10)),
    };
    return result;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to convert base64 to search indices: ${errorMessage}`);
  }
}
