import { describe, expect, it } from 'vitest';
import { deriveEncryptionKeystoreKey, deriveRecoveryKey } from '../../src/keystore-crypto/core';
import { exportSymmetricCryptoKey, genSymmetricKey } from '../../src/symmetric-crypto/keys';
import { AES_KEY_BIT_LENGTH } from '../../src/constants';
import { genMnemonic } from '../../src/utils';

describe('Test keystore key generation functions', () => {
  it('correct symmetric key length', async () => {
    const baseKey = await genSymmetricKey();
    const key = await deriveEncryptionKeystoreKey(baseKey);
    const alg = key.algorithm as AesKeyAlgorithm;
    expect(alg.length).toBe(AES_KEY_BIT_LENGTH);
  });

  it('should give different derived keys for the same baseKey', async () => {
    const codes = genMnemonic();
    const baseKey = await genSymmetricKey();

    const encryptionCryoptoKey = await deriveEncryptionKeystoreKey(baseKey);
    const recoveryCryptoKey = await deriveRecoveryKey(codes);

    const encryptionKey = await exportSymmetricCryptoKey(encryptionCryoptoKey);
    const recoveryKey = await exportSymmetricCryptoKey(recoveryCryptoKey);

    expect(encryptionKey).not.toStrictEqual(recoveryKey);
  });
});
