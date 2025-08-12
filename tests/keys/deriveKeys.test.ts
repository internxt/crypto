import { describe, expect, it } from 'vitest';
import { deriveBitsFromBaseKey } from '../../src/keys/deriveKeys';
import { getEncryptionKeystoreKey } from '../../src/keystore/keys';
import { AES_KEY_BIT_LENGTH } from '../../src/utils/constants';
import { generateSymmetricCryptoKey } from '../../src/core';

describe('Test derive key', () => {
  function createTestInput(size) {
    const result = new Uint8Array(size);
    for (let i = 0; i < size; i++) {
      result[i] = i % 251;
    }
    return result;
  }

  it('correct key length', async () => {
    const context = 'BLAKE3 2019-12-27 16:29:52 test vectors context';
    const baseKey = createTestInput(64);
    const test_length = 128;
    const key = await deriveBitsFromBaseKey(context, baseKey, test_length);
    expect(key.length).toBe(test_length / 8);
  });

  it('correct default key length', async () => {
    const baseKey = await generateSymmetricCryptoKey();
    const key = await getEncryptionKeystoreKey(baseKey);
    const alg = key.algorithm as AesKeyAlgorithm;
    expect(alg.length).toBe(AES_KEY_BIT_LENGTH);
  });
});
