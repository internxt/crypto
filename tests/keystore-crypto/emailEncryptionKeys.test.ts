import { describe, expect, it, vi, beforeEach } from 'vitest';
import {
  createEncryptionAndRecoveryKeystores,
  openEncryptionKeystore,
  openRecoveryKeystore,
} from '../../src/keystore-crypto';
import { XWING_PUBLIC_KEY_LENGTH, XWING_SECRET_KEY_LENGTH } from '../../src/constants';
import { genMnemonic } from '../../src/utils';

describe('Test keystore create/open functions', async () => {
  const mockUserEmail = 'mock user email';
  const mnemonic = genMnemonic();

  beforeEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  it('should successfully create and open encryption keystore', async () => {
    const { encryptionKeystore, recoveryKeystore, recoveryCodes } = await createEncryptionAndRecoveryKeystores(
      mockUserEmail,
      mnemonic,
    );
    const resultEnc = await openEncryptionKeystore(encryptionKeystore, mnemonic);
    const resultRec = await openRecoveryKeystore(recoveryCodes, recoveryKeystore);

    expect(resultEnc).toStrictEqual(resultRec);
    expect(resultEnc.publicKey).instanceOf(Uint8Array);
    expect(resultEnc.secretKey).instanceOf(Uint8Array);
    expect(resultEnc.publicKey.length).toBe(XWING_PUBLIC_KEY_LENGTH);
    expect(resultEnc.secretKey.length).toBe(XWING_SECRET_KEY_LENGTH);
  });

  it('should throw an error if no base key for keystore opening', async () => {
    const { encryptionKeystore, recoveryKeystore } = await createEncryptionAndRecoveryKeystores(
      mockUserEmail,
      mnemonic,
    );

    await expect(openEncryptionKeystore(encryptionKeystore, '')).rejects.toThrowError(
      /Failed to open encryption keystore/,
    );
    await expect(openRecoveryKeystore('', recoveryKeystore)).rejects.toThrowError(/Failed to open recovery keystore/);
  });
});
