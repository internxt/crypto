import { describe, expect, it } from 'vitest';
import { getKeystoreCryptoKey } from '../../src/keystore/utils';
import { AES_ALGORITHM, AES_KEY_BIT_LENGTH } from '../../src/utils/constants';
import { genSymmetricCryptoKey } from '../../src/symmetric/keys';

describe('Test keystore keys functions', () => {
  it('should generate encryption keystore as expected', async () => {
    const baseKey = await genSymmetricCryptoKey();
    const mockContext = 'mock context string';
    const key = await getKeystoreCryptoKey(mockContext, baseKey);

    expect(key).toBeInstanceOf(CryptoKey);
    expect(key.type).toBe('secret');
    expect(key.extractable).toBeTruthy();
    expect(key.usages).toContain('encrypt');
    expect(key.usages).toContain('decrypt');

    const alg = key.algorithm as AesKeyAlgorithm;
    expect(alg.name).toBe(AES_ALGORITHM);
    expect(alg.length).toBe(AES_KEY_BIT_LENGTH);
  });

  it('should generate encryption keystore as expected', async () => {
    const badKey = await window.crypto.subtle.generateKey(
      {
        name: AES_ALGORITHM,
        length: AES_KEY_BIT_LENGTH,
      },
      false,
      ['encrypt', 'decrypt'],
    );
    const mockContext = 'mock context string';
    await expect(getKeystoreCryptoKey(mockContext, badKey)).rejects.toThrowError(/Cannot derive keystore crypto key/);
  });
});
