import { encryptSymmetrically, decryptSymmetrically } from '../symmetric-crypto';
import { base64ToUint8Array, uint8ArrayToBase64, UTF8ToUint8, mnemonicToBytes, publicKeyToBase64 } from '../utils';
import { deriveSymmetricCryptoKeyFromContext } from '../derive-key';
import { CONTEXT_ENC_KEYSTORE, AES_KEY_BIT_LENGTH, CONTEXT_RECOVERY } from '../constants';
import { getBytesFromData } from '../hash';
import { EmailKeys, EncryptedKeystore, KeystoreType } from 'types';
import { exportPrivateKey, importPrivateKey, importPublicKey } from '../asymmetric-crypto';

/**
 * Encrypts the keystore content using symmetric encryption
 *
 * @param secretKey - The symmetric key to encrypt the keystore content
 * @param content - The content of the keystore
 * @param userID - The ID of the user
 * @param tag - The keystore type-specific tag string
 * @returns The encrypted keystore content
 */
export async function encryptKeystoreContent(
  secretKey: CryptoKey,
  keys: EmailKeys,
  userEmail: string,
  type: KeystoreType,
): Promise<EncryptedKeystore> {
  try {
    const aux = UTF8ToUint8(userEmail + type);
    const publicKeys = await publicKeyToBase64(keys.publicKeys);
    const kyberPrivateKeyEnc = await encryptSymmetrically(secretKey, keys.privateKeys.kyberPrivateKey, aux);
    const eccPrivateKey = await exportPrivateKey(keys.privateKeys.eccPrivateKey);
    const eccPrivateKeyEnc = await encryptSymmetrically(secretKey, eccPrivateKey, aux);
    const encryptedKeys = {
      publicKeys,
      privateKeys: {
        kyberPrivateKeyBase64: uint8ArrayToBase64(kyberPrivateKeyEnc),
        eccPrivateKeyBase64: uint8ArrayToBase64(eccPrivateKeyEnc),
      },
    };

    const keystore: EncryptedKeystore = {
      userEmail,
      type,
      encryptedKeys,
    };
    return keystore;
  } catch (error) {
    throw new Error('Failed to encrypt keystore content', { cause: error });
  }
}

/**
 * Decrypts the keystore content using symmetric encryption
 *
 * @param secretKey - The symmetric key to decrypt the keystore content
 * @param encryptedKeys - The encrypted keystore content
 * @param userEmail - The ID of the user
 * @param tag - The keystore type-specific tag string
 * @returns The decrypted keystore content
 */
export async function decryptKeystoreContent(
  secretKey: CryptoKey,
  encryptedKeystore: EncryptedKeystore,
): Promise<EmailKeys> {
  try {
    const aux = UTF8ToUint8(encryptedKeystore.userEmail + encryptedKeystore.type);
    const kyberPublicKey = base64ToUint8Array(encryptedKeystore.encryptedKeys.publicKeys.kyberPublicKeyBase64);
    const eccPublicArray = base64ToUint8Array(encryptedKeystore.encryptedKeys.publicKeys.eccPublicKeyBase64);
    const eccPublicKey = await importPublicKey(eccPublicArray);
    const encKyberPrivateKey = base64ToUint8Array(encryptedKeystore.encryptedKeys.privateKeys.kyberPrivateKeyBase64);
    const kyberPrivateKey = await decryptSymmetrically(secretKey, encKyberPrivateKey, aux);
    const eccEncArray = base64ToUint8Array(encryptedKeystore.encryptedKeys.privateKeys.eccPrivateKeyBase64);
    const eccKey = await decryptSymmetrically(secretKey, eccEncArray, aux);
    const eccPrivateKey = await importPrivateKey(eccKey);
    const keys = {
      publicKeys: {
        kyberPublicKey,
        eccPublicKey,
      },
      privateKeys: {
        kyberPrivateKey,
        eccPrivateKey,
      },
    };
    return keys;
  } catch (error) {
    throw new Error('Failed to decrypt keystore content', { cause: error });
  }
}

/**
 * Derives a secret key for protecting the recovery keystore
 *
 * @param recoveryCodes - The recovery codes
 * @returns The derived secret key for protecting the recovery keystore
 */
export async function deriveRecoveryKey(recoveryCodes: string): Promise<CryptoKey> {
  const recoverCodesArray = mnemonicToBytes(recoveryCodes);
  const recoveryCodesBuffer = getBytesFromData(AES_KEY_BIT_LENGTH / 8, recoverCodesArray);
  return deriveSymmetricCryptoKeyFromContext(CONTEXT_RECOVERY, recoveryCodesBuffer);
}

/**
 * Derives a secret key for protecting the encryption keystore
 *
 * @param baseKey - The base secret key from which a new key secret will be derived
 * @returns The derived secret key for protecting the encryption keystore
 */
export async function deriveEncryptionKeystoreKey(baseKey: Uint8Array): Promise<CryptoKey> {
  return deriveSymmetricCryptoKeyFromContext(CONTEXT_ENC_KEYSTORE, baseKey);
}
