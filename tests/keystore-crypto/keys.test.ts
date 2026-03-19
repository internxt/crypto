import { describe, expect, it } from 'vitest';
import { deriveEncryptionKeystoreKey, deriveRecoveryKey } from '../../src/keystore-crypto/core';
import { genSymmetricKey } from '../../src/symmetric-crypto';
import { AES_KEY_BYTE_LENGTH } from '../../src/constants';
import { genMnemonic } from '../../src/utils';

describe('Test keystore key generation functions', () => {
  it('correct symmetric key length', async () => {
    const baseKey = genSymmetricKey();
    const key = await deriveEncryptionKeystoreKey(baseKey);
    expect(key.length).toBe(AES_KEY_BYTE_LENGTH);
  });

  it('should give different derived keys for the same baseKey', async () => {
    const codes = genMnemonic();
    const baseKey = genSymmetricKey();

    const encryptionKey = await deriveEncryptionKeystoreKey(baseKey);
    const recoveryKey = await deriveRecoveryKey(codes);

    expect(encryptionKey).not.toStrictEqual(recoveryKey);
  });
});
