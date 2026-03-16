import { describe, expect, it } from 'vitest';
import { wrapKey, unwrapKey, deriveWrappingKey } from '../../src/key-wrapper';
import { genSymmetricKey } from '../../src/symmetric-crypto';
import { AES_KEY_BIT_LENGTH } from '../../src/constants';

describe('Test key wrapping functions', () => {
  it('should scuessfully derive wrapping key', async () => {
    const secret1 = genSymmetricKey();
    const secret2 = genSymmetricKey();

    const result = await deriveWrappingKey(secret1, secret2);

    expect(result).toBeInstanceOf(Uint8Array);
    expect(result.length).toBe(AES_KEY_BIT_LENGTH / 8);
  });

  it('should scuessfully wrap and unwrap key', async () => {
    const secret1 = genSymmetricKey();
    const secret2 = genSymmetricKey();

    const wrappingKey = await deriveWrappingKey(secret1, secret2);
    const encryptionKey = genSymmetricKey();

    const ciphertext = await wrapKey(encryptionKey, wrappingKey);
    const result = await unwrapKey(ciphertext, wrappingKey);

    expect(result).toStrictEqual(encryptionKey);
  });

  it('should throw error if secrets are of different length', async () => {
    const ecc = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    const kyber = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9]);
    await expect(deriveWrappingKey(ecc, kyber)).rejects.toThrowError(/Failed to derive wrapping key/);
  });
});
