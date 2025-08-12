import { describe, expect, it } from 'vitest';
import { getEncryptionKeystoreKey } from '../../src/keystore';
import { AES_ALGORITHM, AES_KEY_BIT_LENGTH } from '../../src/utils/constants';
import { genSymmetricCryptoKey } from '../../src/symmetric/keys';

describe('Test keystore keys functions', () => {
  it('should generate encryption keystore as expected', async () => {
    const baseKey = await genSymmetricCryptoKey();
    const key = await getEncryptionKeystoreKey(baseKey);

    expect(key).toBeInstanceOf(CryptoKey);
    expect(key.type).toBe('secret');
    expect(key.extractable).toBeTruthy();
    expect(key.usages).toContain('encrypt');
    expect(key.usages).toContain('decrypt');

    const alg = key.algorithm as AesKeyAlgorithm;
    expect(alg.name).toBe(AES_ALGORITHM);
    expect(alg.length).toBe(AES_KEY_BIT_LENGTH);
  });
});
