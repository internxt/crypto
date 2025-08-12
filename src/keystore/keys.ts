import { CONTEXT_LOGIN, CONTEXT_KEYSTORE, CONTEXT_RECOVERY, CONTEXT_INDEX } from '../utils/constants';

import { deriveKeyFromBaseKey } from '../keys/deriveKeys';
import { importSymmetricKey, exportSymmetricKey } from '../core/symmetric';

async function getKeystoreCryptoKey(context: string, baseKey: CryptoKey): Promise<CryptoKey> {
  try {
    const baseKeyBits = await exportSymmetricKey(baseKey);
    const keyBits = await deriveKeyFromBaseKey(context, baseKeyBits);
    return importSymmetricKey(keyBits);
  } catch (error) {
    return Promise.reject(new Error(`Cannot derive keystore crypto key: ${error}`));
  }
}

export async function getIdentityKeystoreKey(baseKey: CryptoKey): Promise<CryptoKey> {
  return getKeystoreCryptoKey(CONTEXT_LOGIN, baseKey);
}

export async function getEncryptionKeystoreKey(baseKey: CryptoKey): Promise<CryptoKey> {
  return getKeystoreCryptoKey(CONTEXT_KEYSTORE, baseKey);
}

export async function getIndexKey(baseKey: CryptoKey): Promise<CryptoKey> {
  return getKeystoreCryptoKey(CONTEXT_INDEX, baseKey);
}

export async function getRecoveryKey(recoveryCodes: CryptoKey): Promise<CryptoKey> {
  return getKeystoreCryptoKey(CONTEXT_RECOVERY, recoveryCodes);
}
