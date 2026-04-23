import { describe, expect, it, vi, beforeEach } from 'vitest';
import {
  createEncryptionAndRecoveryKeystores,
  openEncryptionKeystore,
  openRecoveryKeystore,
} from '../../src/keystore-crypto';
import { XWING_PUBLIC_KEY_LENGTH, XWING_SECRET_KEY_LENGTH } from '../../src/constants';

describe('Test keystore create/open functions', async () => {
  const mockUserEmail = 'mock user email';

  beforeEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  it('should successfully create and open encryption keystore', async () => {
    const password = 'user password';
    const { encryptionKeystore, recoveryKeystore, recoveryCodes, salt } = await createEncryptionAndRecoveryKeystores(
      mockUserEmail,
      password,
    );
    const resultEnc = await openEncryptionKeystore(encryptionKeystore, password, salt);
    const resultRec = await openRecoveryKeystore(recoveryCodes, recoveryKeystore);

    expect(resultEnc).toStrictEqual(resultRec);
    expect(resultEnc.publicKey).instanceOf(Uint8Array);
    expect(resultEnc.secretKey).instanceOf(Uint8Array);
    expect(resultEnc.publicKey.length).toBe(XWING_PUBLIC_KEY_LENGTH);
    expect(resultEnc.secretKey.length).toBe(XWING_SECRET_KEY_LENGTH);
  });

  it('should throw an error if no password for keystore opening', async () => {
    const password = 'user password';
    const { encryptionKeystore, recoveryKeystore, salt } = await createEncryptionAndRecoveryKeystores(
      mockUserEmail,
      password,
    );

    await expect(openEncryptionKeystore(encryptionKeystore, '', salt)).rejects.toThrowError(
      /Failed to open encryption keystore/,
    );
    await expect(openRecoveryKeystore('', recoveryKeystore)).rejects.toThrowError(/Failed to open recovery keystore/);
  });
});
