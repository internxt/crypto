import { describe, expect, it } from 'vitest';
import { deriveSymmetricKeyFromTwoKeys, deriveSymmetricCryptoKeyFromContext } from '../../src/derive-key';
import { deriveEncryptionKeystoreKey } from '../../src/keystore-crypto';
import { AES_KEY_BIT_LENGTH, AES_ALGORITHM } from '../../src/utils';
import { genSymmetricKey } from '../../src/symmetric-crypto';

describe('Test derive key', () => {
  function createTestInput(size): Uint8Array {
    const result = new Uint8Array(size);
    for (let i = 0; i < size; i++) {
      result[i] = i % 251;
    }
    return result;
  }

  it('should derive symmetric key', async () => {
    const context = 'BLAKE3 2019-12-27 16:29:52 test vectors context';
    const baseKey = createTestInput(32);
    const key = await deriveSymmetricCryptoKeyFromContext(context, baseKey);
    expect(key).instanceOf(CryptoKey);
  });

  it('derive symmetric key should throw an error if context is an empty string', async () => {
    const context = '';
    const baseKey = createTestInput(32);
    await expect(deriveSymmetricCryptoKeyFromContext(context, baseKey)).rejects.toThrowError(
      /Failed to derive CryptoKey from base key and context/,
    );
  });

  it('derive symmetric key should throw an error if base key is too short', async () => {
    const context = 'test context';
    const baseKey = createTestInput(2);
    await expect(deriveSymmetricCryptoKeyFromContext(context, baseKey)).rejects.toThrowError(
      /Failed to derive CryptoKey from base key and context/,
    );
  });

  it('should derive symmetric crypto key', async () => {
    const context = 'BLAKE3 2019-12-27 16:29:52 test vectors context';
    const baseKey = createTestInput(32);
    const key = await deriveSymmetricCryptoKeyFromContext(context, baseKey);
    expect(key).toBeInstanceOf(CryptoKey);
    const alg = key.algorithm as AesKeyAlgorithm;
    expect(alg.name).toBe(AES_ALGORITHM);
    expect(alg.length).toBe(AES_KEY_BIT_LENGTH);
  });

  it('correct symmetric key length', async () => {
    const baseKey = await genSymmetricKey();
    const key = await deriveEncryptionKeystoreKey(baseKey);
    const alg = key.algorithm as AesKeyAlgorithm;
    expect(alg.length).toBe(AES_KEY_BIT_LENGTH);
  });

  it('should derive symmetric key from two keys', async () => {
    const key1 = genSymmetricKey();
    const key2 = genSymmetricKey();
    const context = 'test context';
    const key = await deriveSymmetricKeyFromTwoKeys(key1, key2, context);
    expect(key.length).toBe(AES_KEY_BIT_LENGTH / 8);
  });

  it('derive symmetric key from two keys should fail for small key', async () => {
    const short_key = new Uint8Array([1, 2, 3]);
    const key2 = genSymmetricKey();
    const context = 'test context';
    await expect(deriveSymmetricKeyFromTwoKeys(short_key, key2, context)).rejects.toThrowError(
      /Failed to derive symmetric key from two keys/,
    );
    await expect(deriveSymmetricKeyFromTwoKeys(key2, short_key, context)).rejects.toThrowError(
      /Failed to derive symmetric key from two keys/,
    );
  });
});
