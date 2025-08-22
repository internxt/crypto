import { encryptSymmetrically, decryptSymmetrically } from '../symmetric-crypto';
import { SymmetricCiphertext, base64ToUint8Array, uint8ArrayToBase64 } from '../utils';
import sessionStorageService from '../storage-service/sessionStorageService';

export async function createKeystore(
  secretKey: CryptoKey,
  nonce: number,
  content: string,
  userID: string,
  tag: string,
): Promise<SymmetricCiphertext> {
  try {
    const aux = userID + tag;
    const message = base64ToUint8Array(content);
    const result = await encryptSymmetrically(secretKey, nonce, message, aux);
    return result;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return Promise.reject(new Error(`Failed to create keystore: ${errorMessage}`));
  }
}

export async function openKeystore(
  secretKey: CryptoKey,
  encryptedKeys: SymmetricCiphertext,
  userID: string,
  tag: string,
): Promise<string> {
  try {
    const aux = userID + tag;
    const content = await decryptSymmetrically(secretKey, encryptedKeys, aux);
    const result = uint8ArrayToBase64(content);
    return result;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return Promise.reject(new Error(`Failed to open keystore: ${errorMessage}`));
  }
}

export function getUserID(): string {
  try {
    const userID = sessionStorageService.get('userID');
    if (!userID) {
      throw new Error('No UserID');
    }
    return userID;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to get UserID from session storage: ${errorMessage}`);
  }
}

export function getBaseKey(): Uint8Array {
  try {
    const baseKeyBase64 = sessionStorageService.get('baseKey');
    if (!baseKeyBase64) {
      throw new Error('No base key');
    }
    return base64ToUint8Array(baseKeyBase64);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to get base key from session storage: ${errorMessage}`);
  }
}
