import { CONTEXT_LOGIN, CONTEXT_KEYSTORE, CONTEXT_RECOVERY, CONTEXT_INDEX } from '../utils/constants';
import { getKeystoreCryptoKey } from './utils';

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
