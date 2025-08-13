import { describe, expect, it } from 'vitest';
import {
  deriveBitsFromBaseKey,
  deriveSymmetricKeyFromTwoKeys,
  deriveSymmetricKeyFromBaseKey,
  deriveSymmetricCryptoKeyFromBaseKey,
} from '../../src/derive/deriveKeys';
import { getEncryptionKeystoreKey } from '../../src/keystore/keys';
import { AES_KEY_BIT_LENGTH, AES_ALGORITHM } from '../../src/utils/constants';
import { genSymmetricCryptoKey, genSymmetricKey } from '../../src/symmetric/keys';

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
    const baseKey = createTestInput(64);
    const key = await deriveSymmetricKeyFromBaseKey(context, baseKey);
    expect(key.length).toBe(AES_KEY_BIT_LENGTH / 8);
  });

  it('derive symmetric key should throw an error if context is null', async () => {
    const context = null as any;
    const baseKey = createTestInput(64);
    await expect(deriveSymmetricKeyFromBaseKey(context, baseKey)).rejects.toThrowError(
      /Key derivation from base key failed/,
    );
  });

  it('should derive symmetric crypto key', async () => {
    const context = 'BLAKE3 2019-12-27 16:29:52 test vectors context';
    const baseKey = createTestInput(64);
    const key = await deriveSymmetricCryptoKeyFromBaseKey(context, baseKey);
    expect(key).toBeInstanceOf(CryptoKey);
    const alg = key.algorithm as AesKeyAlgorithm;
    expect(alg.name).toBe(AES_ALGORITHM);
    expect(alg.length).toBe(AES_KEY_BIT_LENGTH);
  });

  it('derive symmetric crypto key should throw an error if context is null', async () => {
    const context = null as any;
    const baseKey = createTestInput(64);
    await expect(deriveSymmetricCryptoKeyFromBaseKey(context, baseKey)).rejects.toThrowError(
      /CryptoKey derivation from base key failed/,
    );
  });

  it('should derive the specified number of bits', async () => {
    const context = 'BLAKE3 2019-12-27 16:29:52 test vectors context';
    const baseKey = createTestInput(64);
    const test_length = 128;
    const key = await deriveBitsFromBaseKey(context, baseKey, test_length);
    expect(key.length).toBe(test_length / 8);
  });

  it('bits derivation should throw an error if number of bits is not multiple to 8', async () => {
    const context = 'BLAKE3 2019-12-27 16:29:52 test vectors context';
    const baseKey = createTestInput(64);
    const test_length = 127;
    await expect(deriveBitsFromBaseKey(context, baseKey, test_length)).rejects.toThrowError(
      /Bit derivation from base key failed/,
    );
  });

  it('correct symmetric key length', async () => {
    const baseKey = await genSymmetricCryptoKey();
    const key = await getEncryptionKeystoreKey(baseKey);
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
    await expect(deriveSymmetricKeyFromTwoKeys(short_key, key2, context)).rejects.toThrowError(/Key derivation failed/);
    await expect(deriveSymmetricKeyFromTwoKeys(key2, short_key, context)).rejects.toThrowError(/Key derivation failed/);
  });
});
