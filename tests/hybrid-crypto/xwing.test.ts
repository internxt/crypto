import { describe, expect, it } from 'vitest';
import { decapsulateHybrid, encapsulateHybrid, genHybridKeys } from '../../src/hybrid-crypto';
import {
  XWING_PUBLIC_KEY_LENGTH,
  XWING_SECRET_KEY_LENGTH,
  XWING_SEED_BYTE_LENGTH,
  XWING_CIPHERTEXT_BYTE_LENGTH,
} from '../../src/constants';
import { randomBytes } from '@noble/hashes/utils.js';

describe('Test key wrapping functions', () => {
  it('should scuessfully generate hybrid key', async () => {
    const keys = genHybridKeys();

    expect(keys.publicKey).toBeInstanceOf(Uint8Array);
    expect(keys.secretKey).toBeInstanceOf(Uint8Array);

    expect(keys.publicKey.length).toBe(XWING_PUBLIC_KEY_LENGTH);
    expect(keys.secretKey.length).toBe(XWING_SECRET_KEY_LENGTH);
  });

  it('should generate identical keys for identical seeds', async () => {
    const seed = randomBytes(XWING_SEED_BYTE_LENGTH);
    const keys1 = genHybridKeys(seed);
    const keys2 = genHybridKeys(seed);

    expect(keys1).toStrictEqual(keys2);
  });

  it('should sucessufully decapsulate encapsulated secret', async () => {
    const keys = genHybridKeys();
    const { cipherText, sharedSecret } = encapsulateHybrid(keys.publicKey);
    expect(cipherText.length).toBe(XWING_CIPHERTEXT_BYTE_LENGTH);

    const result = decapsulateHybrid(cipherText, keys.secretKey);

    expect(result).toStrictEqual(sharedSecret);
    expect(result).toBeInstanceOf(Uint8Array);
    expect(result.length).toBe(XWING_SECRET_KEY_LENGTH);
  });
});
