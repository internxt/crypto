import { describe, expect, it } from 'vitest';
import { deriveEncryptionKeystoreKey, deriveRecoveryKey } from '../../src/keystore-crypto/core';
import { AES_KEY_BYTE_LENGTH } from '../../src/constants';
import { genMnemonic } from '../../src/utils';

describe('Test keystore key generation functions', () => {
  it('correct symmetric key length', async () => {
    const mnemonic = genMnemonic();
    const key = await deriveEncryptionKeystoreKey(mnemonic);
    expect(key.length).toBe(AES_KEY_BYTE_LENGTH);
  });

  it('should give different derived keys for the same baseKey', async () => {
    const codes = genMnemonic();
    const mnemonic = genMnemonic();

    const encryptionKey = await deriveEncryptionKeystoreKey(mnemonic);
    const recoveryKey = await deriveRecoveryKey(codes);

    expect(encryptionKey).not.toStrictEqual(recoveryKey);
  });
});
