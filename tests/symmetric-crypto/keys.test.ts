import { describe, expect, it } from 'vitest';
import { exportSymmetricCryptoKey, genSymmetricCryptoKey, genSymmetricKey } from '../../src/symmetric-crypto';
import { AES_ALGORITHM, AES_KEY_BIT_LENGTH } from '../../src/constants';

describe('Test symmetric key functions', () => {
  it('should sucessfully generate crypto key', async () => {
    const key = await genSymmetricCryptoKey();

    expect(key).toBeInstanceOf(CryptoKey);
    expect(key.type).toBe('secret');
    expect(key.extractable).toBeTruthy();
    expect(key.usages).toContain('encrypt');
    expect(key.usages).toContain('decrypt');

    const alg = key.algorithm as AesKeyAlgorithm;
    expect(alg.name).toBe(AES_ALGORITHM);
    expect(alg.length).toBe(AES_KEY_BIT_LENGTH);
  });

  it('should sucessfully generate key', async () => {
    const key = genSymmetricKey();

    expect(key).toBeInstanceOf(Uint8Array);
    expect(key.length).toBe(AES_KEY_BIT_LENGTH / 8);
  });

  it('should throw an error if secret key is non exportable', async () => {
    const non_exportable_key = await window.crypto.subtle.generateKey(
      {
        name: AES_ALGORITHM,
        length: AES_KEY_BIT_LENGTH,
      },
      false,
      ['encrypt', 'decrypt'],
    );
    await expect(exportSymmetricCryptoKey(non_exportable_key)).rejects.toThrowError(
      /Failed to export symmetric CryptoKey/,
    );
  });
});
