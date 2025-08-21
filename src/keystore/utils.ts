import { encryptSymmetrically, decryptSymmetrically } from '../symmetric';
import { Buffer } from 'buffer';
import { SymmetricCiphertext, base64ToUint8Array } from '../utils';
import sessionStorageService from '../utils/sessionStorageService';

export async function createKeystore(
  secretKey: CryptoKey,
  nonce: number,
  content: string,
  userID: string,
  tag: string,
): Promise<SymmetricCiphertext> {
  const aux = userID + tag;
  return await encryptSymmetrically(secretKey, nonce, Buffer.from(content), aux);
}

export async function openKeystore(
  secretKey: CryptoKey,
  encryptedKeys: SymmetricCiphertext,
  userID: string,
  tag: string,
): Promise<string> {
  const aux = userID + tag;
  const content = await decryptSymmetrically(secretKey, encryptedKeys, aux);
  const result = Buffer.from(content).toString('utf-8');
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
