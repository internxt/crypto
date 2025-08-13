import { deriveSymmetricKeyFromBaseKey } from '../derive/deriveKeys';
import {
  importSymmetricCryptoKey,
  exportSymmetricCryptoKey,
  encryptSymmetrically,
  decryptSymmetrically,
} from '../symmetric';
import { Buffer } from 'buffer';
import { EncryptedKeystore } from '../utils/types';

export async function getKeystoreCryptoKey(context: string, baseKey: CryptoKey): Promise<CryptoKey> {
  try {
    const baseKeyBits = await exportSymmetricCryptoKey(baseKey);
    const keyBits = await deriveSymmetricKeyFromBaseKey(context, baseKeyBits);
    return importSymmetricCryptoKey(keyBits);
  } catch (error) {
    return Promise.reject(new Error(`Cannot derive keystore crypto key: ${error}`));
  }
}

export async function createKeystore(
  secretKey: CryptoKey,
  nonce: number,
  content: string,
  userID: string,
  tag: string,
): Promise<EncryptedKeystore> {
  const aux = userID + tag;
  const { ciphertext, iv } = await encryptSymmetrically(secretKey, nonce, Buffer.from(content), aux);
  return { encryptedKeys: ciphertext, iv };
}

export async function openKeystore(
  secretKey: CryptoKey,
  iv: Uint8Array,
  encryptedKeys: Uint8Array,
  userID: string,
  tag: string,
): Promise<string> {
  const aux = userID + tag;
  const content = await decryptSymmetrically(secretKey, iv, encryptedKeys, aux);
  const result = Buffer.from(content).toString('utf-8');
  return result;
}
