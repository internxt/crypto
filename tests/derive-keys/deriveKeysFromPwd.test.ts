import { describe, expect, it, vi } from 'vitest';
import {
  getKeyFromPasswordAndSalt,
  verifyKeyFromPasswordHex,
  getKeyFromPasswordAndSaltHex,
  getKeyFromPasswordHex,
  getKeyFromPassword,
} from '../../src/derive-key/deriveKeysFromPwd';

import { argon2, sampleSalt } from '../../src/derive-key/utils';
import { uint8ArrayToHex } from '../../src/utils';

describe('Test Argon2', () => {
  it('should get correct key from the password', async () => {
    const TEST_ARGON2_PARALLELISM = 7;
    const TEST_ARGON2_ITERATIONS = 20;
    const TEST_ARGON2_MEMORY_SIZE = 56;
    const TEST_ARGON2_TAG_LENGTH = 32;

    const test_password = 'text demo';
    const test_salt = new Uint8Array([245, 166, 56, 228, 15, 96, 226, 174, 51, 22, 161, 34, 245, 194, 243, 16]);

    const result = await argon2(
      test_password,
      test_salt,
      TEST_ARGON2_PARALLELISM,
      TEST_ARGON2_ITERATIONS,
      TEST_ARGON2_MEMORY_SIZE,
      TEST_ARGON2_TAG_LENGTH,
    );
    const resultHEX = uint8ArrayToHex(result);
    expect(resultHEX).toBe('53b7d7e24871060915166e96148bab3f6c9ff2a713eb2705e4ff19159aa7ebfb');
  });

  it('should generate different salt each time', async () => {
    const test_salt_1 = uint8ArrayToHex(sampleSalt());
    const test_salt_2 = uint8ArrayToHex(sampleSalt());
    expect(test_salt_1).not.toBe(test_salt_2);
  });

  it('should sucessfully verify generated from the password and salt key', async () => {
    const test_password = 'text demo';
    const test_salt = uint8ArrayToHex(sampleSalt());
    const test_key = await getKeyFromPasswordAndSaltHex(test_password, test_salt);
    const result = await verifyKeyFromPasswordHex(test_password, test_salt, test_key);
    expect(result).toBe(true);
  });

  it('should give the same result for the same password and salt', async () => {
    const test_password = 'text demo';
    const test_salt = uint8ArrayToHex(sampleSalt());
    const result1 = await getKeyFromPasswordAndSalt(test_password, test_salt);
    const result2 = await getKeyFromPasswordAndSalt(test_password, test_salt);
    expect(result1).toStrictEqual(result2);
  });

  it('should give different result for the same password but different salt', async () => {
    const test_password = 'text demo';
    const test_salt_1 = uint8ArrayToHex(sampleSalt());
    const test_salt_2 = uint8ArrayToHex(sampleSalt());
    const result1 = await getKeyFromPasswordAndSaltHex(test_password, test_salt_1);
    const result2 = await getKeyFromPasswordAndSaltHex(test_password, test_salt_2);
    expect(result1).not.toBe(result2);
  });

  it('should sucessfully verify generated from the password key', async () => {
    const test_password = 'text demo';
    const { keyHex: hash, saltHex: salt } = await getKeyFromPasswordHex(test_password);
    const result = await verifyKeyFromPasswordHex(test_password, salt, hash);
    expect(result).toBe(true);
  });

  it('should throw an error if key derivation failed', async () => {
    const test_password = 'text demo';

    const originalGenerateRandomValues = window.crypto.getRandomValues;

    window.crypto.getRandomValues = vi.fn(() => {
      throw new Error('simulated failure');
    }) as any;

    await expect(getKeyFromPassword(test_password)).rejects.toThrowError(/Failed to derive key from password/);
    await expect(getKeyFromPasswordHex(test_password)).rejects.toThrowError(/Failed to derive key from password/);

    window.crypto.getRandomValues = originalGenerateRandomValues;
  });
});
