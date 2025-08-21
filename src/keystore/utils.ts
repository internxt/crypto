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
  const aux = userID + tag;
  const message = base64ToUint8Array(content);
  const result = await encryptSymmetrically(secretKey, nonce, message, aux);
  return result;
}

export async function openKeystore(
  secretKey: CryptoKey,
  encryptedKeys: SymmetricCiphertext,
  userID: string,
  tag: string,
): Promise<string> {
  const aux = userID + tag;
  const content = await decryptSymmetrically(secretKey, encryptedKeys, aux);
  const result = uint8ArrayToBase64(content);
  return result;
}

export function getUserID(): string {
  try {
    const userID = sessionStorageService.get('userID');
    if (!userID) {
      throw new Error('No UserID');
    }
    return userID;
  } catch (error) {
    throw new Error('Cannot get UserID from session storage', error);
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
    throw new Error('Cannot get base key from session storage', error);
  }
}
