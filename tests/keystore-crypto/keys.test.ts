import { describe, expect, it } from 'vitest';
import { deriveEncryptionKeystoreKey, deriveRecoveryKey } from '../../src/keystore-crypto/core';
import { AES_KEY_BYTE_LENGTH } from '../../src/constants';
import { genMnemonic } from '../../src/utils';
import { generateSalt } from '../../src/derive-password';

describe('Test keystore key generation functions', () => {
  it('correct symmetric key length', async () => {
    const password = 'user password';
    const salt = generateSalt();
    const key = await deriveEncryptionKeystoreKey(password, salt);
    expect(key.length).toBe(AES_KEY_BYTE_LENGTH);
  });

  it('should give different derived keys for the same baseKey', async () => {
    const codes = genMnemonic();
    const password = 'user password';
    const salt = generateSalt();

    const encryptionKey = await deriveEncryptionKeystoreKey(password, salt);
    const recoveryKey = await deriveRecoveryKey(codes);

    expect(encryptionKey).not.toStrictEqual(recoveryKey);
  });
});
