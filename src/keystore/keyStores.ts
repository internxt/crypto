import { IdentityKeys, EncryptionKeys } from '../utils/types';
import { encryptSymmetrically, decryptSymmetrically } from '../core/symmetric';
import { Buffer } from 'buffer';
import { IDENTITY_KEYSTORE_TAG, ENCRYPTION_KEYSTORE_TAG, RECOVERY_KEYSTORE_TAG } from '../utils/constants';

export async function createIdentityKeystore(
  secretKey: CryptoKey,
  nonce: number,
  keys: IdentityKeys,
  userID: string,
): Promise<{ ciphertext: Uint8Array; iv: Uint8Array }> {
  const content = JSON.stringify(keys);
  const aux = userID + IDENTITY_KEYSTORE_TAG;
  return encryptSymmetrically(secretKey, nonce, Buffer.from(content), aux);
}

export async function openIdentityKeystore(
  secretKey: CryptoKey,
  iv: Uint8Array,
  encryptedKeys: Uint8Array,
  userID: string,
): Promise<IdentityKeys> {
  const aux = userID + IDENTITY_KEYSTORE_TAG;
  const content = await decryptSymmetrically(secretKey, iv, encryptedKeys, aux);
  const json = Buffer.from(content).toString('utf-8');
  const keys: IdentityKeys = JSON.parse(json);
  return keys;
}

export async function createEncryptionKeystore(
  secretKey: CryptoKey,
  nonce: number,
  keys: EncryptionKeys,
  userID: string,
): Promise<{ ciphertext: Uint8Array; iv: Uint8Array }> {
  const content = JSON.stringify(keys);
  const aux = userID + ENCRYPTION_KEYSTORE_TAG;
  return encryptSymmetrically(secretKey, nonce, Buffer.from(content), aux);
}

export async function openEncryptionKeystore(
  secretKey: CryptoKey,
  iv: Uint8Array,
  encryptedKeys: Uint8Array,
  userID: string,
): Promise<EncryptionKeys> {
  const aux = userID + ENCRYPTION_KEYSTORE_TAG;
  const content = await decryptSymmetrically(secretKey, iv, encryptedKeys, aux);
  const json = Buffer.from(content).toString('utf-8');
  const keys: EncryptionKeys = JSON.parse(json);
  return keys;
}

export async function createRecoveryKeystore(
  recoveryKey: CryptoKey,
  nonce: number,
  keys: EncryptionKeys,
  userID: string,
): Promise<{ ciphertext: Uint8Array; iv: Uint8Array }> {
  const content = JSON.stringify(keys);
  const aux = userID + RECOVERY_KEYSTORE_TAG;
  return encryptSymmetrically(recoveryKey, nonce, Buffer.from(content), aux);
}

export async function openRecoveryKeystore(
  recoveryKey: CryptoKey,
  iv: Uint8Array,
  encryptedKeys: Uint8Array,
  userID: string,
): Promise<EncryptionKeys> {
  const aux = userID + RECOVERY_KEYSTORE_TAG;
  const content = await decryptSymmetrically(recoveryKey, iv, encryptedKeys, aux);
  const json = Buffer.from(content).toString('utf-8');
  const keys: EncryptionKeys = JSON.parse(json);
  return keys;
}
