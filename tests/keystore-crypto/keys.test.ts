import { describe, expect, it } from 'vitest';
import { deriveEncryptionKeystoreKey, deriveRecoveryKey } from '../../src/keystore-crypto/core';
import { genSymmetricKey } from '../../src/symmetric-crypto/keys';
import { AES_KEY_BIT_LENGTH } from '../../src/constants';
import { genMnemonic } from '../../src/utils';

describe('Test keystore key generation functions', () => {
  it('correct symmetric key length', async () => {
    const baseKey = await genSymmetricKey();
    const key = await deriveEncryptionKeystoreKey(baseKey);
    expect(key.length).toBe(AES_KEY_BIT_LENGTH / 8);
  });

  it('should give different derived keys for the same baseKey', async () => {
    const codes = genMnemonic();
    const baseKey = await genSymmetricKey();

    const encryptionKey = await deriveEncryptionKeystoreKey(baseKey);
    const recoveryKey = await deriveRecoveryKey(codes);

    expect(encryptionKey).not.toStrictEqual(recoveryKey);
  });
});
