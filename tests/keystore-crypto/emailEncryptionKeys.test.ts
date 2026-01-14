import { describe, expect, it, vi, beforeEach } from 'vitest';
import {
  createEncryptionAndRecoveryKeystores,
  openEncryptionKeystore,
  openRecoveryKeystore,
} from '../../src/keystore-crypto';
import { genSymmetricKey } from '../../src/symmetric-crypto';
import { KYBER768_PUBLIC_KEY_LENGTH, KYBER768_SECRET_KEY_LENGTH } from '../../src/constants';

describe('Test keystore create/open functions', async () => {
  const mockUserEmail = 'mock user email';
  const secretKey = await genSymmetricKey();

  beforeEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  it('should successfully create and open encryption keystore', async () => {
    const { encryptionKeystore, recoveryKeystore, recoveryCodes } = await createEncryptionAndRecoveryKeystores(
      mockUserEmail,
      secretKey,
    );
    const result_enc = await openEncryptionKeystore(encryptionKeystore, secretKey);
    const result_rec = await openRecoveryKeystore(recoveryCodes, recoveryKeystore);

    expect(result_enc).toStrictEqual(result_rec);
    expect(result_enc.privateKeys.eccPrivateKey).instanceOf(CryptoKey);
    expect(result_enc.publicKeys.eccPublicKey).instanceOf(CryptoKey);
    expect(result_enc.privateKeys.kyberPrivateKey.length).toBe(KYBER768_SECRET_KEY_LENGTH);
    expect(result_enc.publicKeys.kyberPublicKey.length).toBe(KYBER768_PUBLIC_KEY_LENGTH);
  });

  it('should throw an error if no base key for keystore opening', async () => {
    const { encryptionKeystore, recoveryKeystore } = await createEncryptionAndRecoveryKeystores(
      mockUserEmail,
      secretKey,
    );

    await expect(openEncryptionKeystore(encryptionKeystore, new Uint8Array([]))).rejects.toThrowError(
      /Failed to open encryption keystore/,
    );
    await expect(openRecoveryKeystore('', recoveryKeystore)).rejects.toThrowError(/Failed to open recovery keystore/);
  });
});
