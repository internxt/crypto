import { encryptSymmetrically, decryptSymmetrically } from '../symmetric-crypto';
import { base64ToUint8Array, uint8ArrayToBase64, UTF8ToUint8 } from '../utils';
import { deriveKeyFromMnemonic } from '../derive-key';
import { CONTEXT_ENC_KEYSTORE, CONTEXT_RECOVERY } from '../constants';
import { EncryptedKeystore, HybridKeyPair, KeystoreType } from '../types';

/**
 * Encrypts the user's hybrid key using symmetric encryption to get a keystore
 *
 * @param secretKey - The symmetric key to encrypt the keystore content
 * @param key - The hybrid key pair
 * @param userEmail - The email of the user
 * @param type - The keystore type
 * @returns The encrypted keystore
 */
export async function encryptKeystoreContent(
  secretKey: Uint8Array,
  keys: HybridKeyPair,
  userEmail: string,
  type: KeystoreType,
): Promise<EncryptedKeystore> {
  try {
    const aux = UTF8ToUint8(userEmail + type);
    const publicKey = uint8ArrayToBase64(keys.publicKey);
    const secretKeyEncrypted = await encryptSymmetrically(secretKey, keys.secretKey, aux);

    const keystore: EncryptedKeystore = {
      userEmail,
      type,
      publicKey,
      privateKeyEncrypted: uint8ArrayToBase64(secretKeyEncrypted),
    };
    return keystore;
  } catch (error) {
    throw new Error('Failed to encrypt keystore content', { cause: error });
  }
}

/**
 * Decrypts the keystore content using symmetric encryption
 *
 * @param kesytoreOpeningKey - The symmetric key to decrypt the keystore content
 * @param encryptedKeys - The encrypted keystore content
 * @returns The decrypted hybrid key pair contained in the keystore
 */
export async function decryptKeystoreContent(
  kesytoreOpeningKey: Uint8Array,
  encryptedKeystore: EncryptedKeystore,
): Promise<HybridKeyPair> {
  try {
    const aux = UTF8ToUint8(encryptedKeystore.userEmail + encryptedKeystore.type);
    const publicKey = base64ToUint8Array(encryptedKeystore.publicKey);
    const ciphertext = base64ToUint8Array(encryptedKeystore.privateKeyEncrypted);
    const secretKey = await decryptSymmetrically(kesytoreOpeningKey, ciphertext, aux);
    return {
      publicKey,
      secretKey,
    };
  } catch (error) {
    throw new Error('Failed to decrypt keystore content', { cause: error });
  }
}

/**
 * Derives a secret key for protecting the recovery keystore
 *
 * @param recoveryCodes - The recovery codes (machine-generated with secure PRNG)
 * @returns The derived secret key for protecting the recovery keystore
 */
export async function deriveRecoveryKey(recoveryCodes: string): Promise<Uint8Array> {
  return deriveKeyFromMnemonic(recoveryCodes, CONTEXT_RECOVERY);
}

/**
 * Derives a secret key for protecting the encryption keystore
 *
 * @param mnemonic - The user's mnemonic (machine-generated with secure PRNG)
 * @returns The derived secret key for protecting the encryption keystore
 */
export async function deriveEncryptionKeystoreKey(mnemonic: string): Promise<Uint8Array> {
  return deriveKeyFromMnemonic(mnemonic, CONTEXT_ENC_KEYSTORE);
}
