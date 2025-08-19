import { CONTEXT_LOGIN, CONTEXT_KEYSTORE, CONTEXT_RECOVERY, CONTEXT_INDEX } from '../utils/constants';
import { getKeystoreCryptoKey } from './utils';

export async function deriveIdentityKeystoreKey(baseKey: CryptoKey): Promise<CryptoKey> {
  return getKeystoreCryptoKey(CONTEXT_LOGIN, baseKey);
}

export async function deriveEncryptionKeystoreKey(baseKey: CryptoKey): Promise<CryptoKey> {
  return getKeystoreCryptoKey(CONTEXT_KEYSTORE, baseKey);
}

export async function deriveIndexKey(baseKey: CryptoKey): Promise<CryptoKey> {
  return getKeystoreCryptoKey(CONTEXT_INDEX, baseKey);
}

export async function deriveRecoveryKey(recoveryCodes: CryptoKey): Promise<CryptoKey> {
  return getKeystoreCryptoKey(CONTEXT_RECOVERY, recoveryCodes);
}
