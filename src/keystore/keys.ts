import { generateEccKeys } from '../asymmetric-crypto';
import { generateKyberKeys } from '../post-quantum-crypto';
import {
  IdentityKeys,
  EncryptionKeys,
  AES_KEY_BIT_LENGTH,
  genMnemonic,
  CONTEXT_LOGIN,
  CONTEXT_KEYSTORE,
  CONTEXT_RECOVERY,
  CONTEXT_INDEX,
} from '../utils';
import { deriveSymmetricCryptoKeyFromContext } from '../derive-key';
import { getHash } from '../hash';

/**
 * Generates recovery codes
 * @returns The generated recovery codes
 */
export function generateRecoveryCodes(): string {
  return genMnemonic(AES_KEY_BIT_LENGTH);
}

/**
 * Generates idenity keys
 * @returns The generated identity keys
 */
export async function generateIdentityKeys(): Promise<IdentityKeys> {
  try {
    const keyPair = await generateEccKeys();
    const result: IdentityKeys = {
      userPrivateKey: keyPair.privateKey,
      userPublicKey: keyPair.publicKey,
    };
    return result;
  } catch (error) {
    return Promise.reject(new Error(`Could not generate idenity keys: ${error}`));
  }
}

/**
 * Generates encryption keys
 * @returns The generated encryption keys
 */
export async function generateEncryptionKeys(): Promise<EncryptionKeys> {
  try {
    const keyPair = await generateEccKeys();
    const keyPairKyber = await generateKyberKeys();
    const result: EncryptionKeys = {
      userPrivateKey: keyPair.privateKey,
      userPublicKey: keyPair.publicKey,
      userPublicKyberKey: keyPairKyber.publicKey,
      userPrivateKyberKey: keyPairKyber.secretKey,
    };
    return result;
  } catch (error) {
    return Promise.reject(new Error(`Could not generate encryption keys: ${error}`));
  }
}

/**
 * Derives a secret key for protecting the idenity keystore
 * @param baseKey - The base secret key from which a new key secret will be derived
 * @returns The derived secret key for protecting the idenity keystore
 */
export async function deriveIdentityKeystoreKey(baseKey: Uint8Array): Promise<CryptoKey> {
  return deriveSymmetricCryptoKeyFromContext(CONTEXT_LOGIN, baseKey);
}

/**
 * Derives a secret key for protecting the encryption keystore
 * @param baseKey - The base secret key from which a new key secret will be derived
 * @returns The derived secret key for protecting the encryption keystore

*/
export async function deriveEncryptionKeystoreKey(baseKey: Uint8Array): Promise<CryptoKey> {
  return deriveSymmetricCryptoKeyFromContext(CONTEXT_KEYSTORE, baseKey);
}

/**
 * Derives a secret key for protecting the index keystore
 * @param baseKey - The base secret key from which a new key secret will be derived
 * @returns The derived secret key for protecting the index keystore
 */
export async function deriveIndexKey(baseKey: Uint8Array): Promise<CryptoKey> {
  return deriveSymmetricCryptoKeyFromContext(CONTEXT_INDEX, baseKey);
}

/**
 * Derives a secret key for protecting the recovery keystore
 * @param recoveryCodes - The recovery codes
 * @returns The derived secret key for protecting the idenity keystore
 */
export async function deriveRecoveryKey(recoveryCodes: string): Promise<CryptoKey> {
  const recoveryCodesBuffer = await getHash(AES_KEY_BIT_LENGTH, [recoveryCodes]);
  return deriveSymmetricCryptoKeyFromContext(CONTEXT_RECOVERY, recoveryCodesBuffer);
}
