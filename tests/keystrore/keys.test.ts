import { describe, expect, it } from 'vitest';
import {
  deriveEncryptionKeystoreKey,
  deriveIdentityKeystoreKey,
  deriveIndexKey,
  deriveRecoveryKey,
} from '../../src/keystore';
import { genSymmetricCryptoKey, exportSymmetricCryptoKey } from '../../src/symmetric/keys';

describe('Test keystore key generation functions', () => {
  it('should give different derived keys for the same baseKey', async () => {
    const baseKey = await genSymmetricCryptoKey();

    const identityCryptoKey = await deriveIdentityKeystoreKey(baseKey);
    const encryptionCryoptoKey = await deriveEncryptionKeystoreKey(baseKey);
    const indexCryptoKey = await deriveIndexKey(baseKey);
    const recoveryCryptoKey = await deriveRecoveryKey(baseKey);

    const identityKey = await exportSymmetricCryptoKey(identityCryptoKey);
    const encryptionKey = await exportSymmetricCryptoKey(encryptionCryoptoKey);
    const indexKey = await exportSymmetricCryptoKey(indexCryptoKey);
    const recoveryKey = await exportSymmetricCryptoKey(recoveryCryptoKey);

    expect(identityKey).not.toStrictEqual(encryptionKey);
    expect(identityKey).not.toStrictEqual(indexKey);
    expect(identityKey).not.toStrictEqual(recoveryKey);

    expect(encryptionKey).not.toStrictEqual(indexKey);
    expect(encryptionKey).not.toStrictEqual(recoveryKey);

    expect(indexKey).not.toStrictEqual(recoveryKey);
  });
});
