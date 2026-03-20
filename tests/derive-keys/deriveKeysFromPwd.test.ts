import { describe, expect, it } from 'vitest';
import { getKeyFromPasswordAndSalt, getKeyFromPassword } from '../../src/derive-key';

import { argon2, sampleSalt } from '../../src/derive-key/core';
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

  it('should give the same result for the same password and salt', async () => {
    const test_password = 'text demo';
    const test_salt = sampleSalt();
    const result1 = await getKeyFromPasswordAndSalt(test_password, test_salt);
    const result2 = await getKeyFromPasswordAndSalt(test_password, test_salt);
    expect(result1).toStrictEqual(result2);
  });

  it('should throw an error if no password is given', async () => {
    await expect(getKeyFromPassword('')).rejects.toThrowError(/Failed to derive key from password/);
  });

  it('should throw an error if no salt or password given', async () => {
    const test_password = 'text demo';
    const test_salt = sampleSalt();
    await expect(getKeyFromPasswordAndSalt(test_password, new Uint8Array())).rejects.toThrowError(
      /Failed to derive key from password and salt/,
    );
    await expect(getKeyFromPasswordAndSalt('', test_salt)).rejects.toThrowError(
      /Failed to derive key from password and salt/,
    );
  });
});
