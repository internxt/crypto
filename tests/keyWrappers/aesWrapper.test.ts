import { describe, expect, it } from 'vitest';
import { wrapKey, unwrapKey, deriveWrappingKey, importWrappingKey } from '../../src/keyWrappers/aesWrapper';
import { genSymmetricCryptoKey } from '../../src/symmetric/keys';
import { KEY_WRAPPING_ALGORITHM, AES_KEY_BIT_LENGTH } from '../../src/utils/constants';
import { generateEccKeys } from '../../src/asymmetric';

describe('Test key wrapping functions', () => {
  it('should scuessfully derive wrapping key', async () => {
    const secret1 = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    const secret2 = new Uint8Array([11, 12, 13, 14, 15, 16, 17, 18, 19, 20]);

    const result = await deriveWrappingKey(secret1, secret2);

    expect(result).toBeInstanceOf(CryptoKey);
    expect(result.extractable).toBeFalsy();
    expect(result.type).toBe('secret');
    expect(result.usages).toContain('wrapKey');
    expect(result.usages).toContain('unwrapKey');

    const alg = result.algorithm as AesKeyAlgorithm;
    expect(alg.name).toBe(KEY_WRAPPING_ALGORITHM);
    expect(alg.length).toBe(AES_KEY_BIT_LENGTH);
  });

  it('should scuessfully wrap and unwrap key', async () => {
    const secret1 = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    const secret2 = new Uint8Array([11, 12, 13, 14, 15, 16, 17, 18, 19, 20]);

    const wrappingKey = await deriveWrappingKey(secret1, secret2);
    const encryptionKey = await genSymmetricCryptoKey();

    const ciphertext = await wrapKey(encryptionKey, wrappingKey);
    const result = await unwrapKey(ciphertext, wrappingKey);

    expect(result).toStrictEqual(encryptionKey);
  });
  it('should scuessfully import the key', async () => {
    const key = new Uint8Array(16);
    window.crypto.getRandomValues(key);

    await expect(importWrappingKey(key)).resolves.toBeInstanceOf(CryptoKey);
  });

  it('should throw error if cannot import wrapping key', async () => {
    const bad_key = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

    await expect(importWrappingKey(bad_key)).rejects.toThrowError(/Failed to import wrapping key:/);
  });

  it('should throw error if cannot unwrapKey key', async () => {
    const key_pair = await generateEccKeys();
    const bad_key = key_pair.privateKey;

    const encrypted = new Uint8Array(16);
    window.crypto.getRandomValues(encrypted);

    await expect(unwrapKey(encrypted, bad_key)).rejects.toThrowError(/Failed to unwrap key:/);
  });

  it('should throw error if cannot wrap key', async () => {
    const key_pair = await generateEccKeys();
    const bad_key = key_pair.privateKey;

    await expect(wrapKey(bad_key, bad_key)).rejects.toThrowError(/Failed to wrap key:/);
  });

  it('should throw error if secrets are of different length', async () => {
    const ecc = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    const kyber = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9]);
    await expect(deriveWrappingKey(ecc, kyber)).rejects.toThrowError(/Failed to derive wrapping key:/);
  });
});
