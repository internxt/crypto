import { describe, expect, it } from 'vitest';
import { getKeyFromPasswordAndSalt, getKeyFromPassword } from '../../src/derive-password';

import { argon2, sampleSalt } from '../../src/derive-password/core';
import { uint8ArrayToHex } from '../../src/utils';

describe('Test Argon2', () => {
  const testPassword = 'text demo';
  const testSalt = sampleSalt();

  it('should get correct key from the password', async () => {
    const testParallelism = 7;
    const testIterations = 20;
    const testMemorySize = 56;
    const testTagLength = 32;

    const testSaltArray = new Uint8Array([245, 166, 56, 228, 15, 96, 226, 174, 51, 22, 161, 34, 245, 194, 243, 16]);

    const result = await argon2(
      testPassword,
      testSaltArray,
      testParallelism,
      testIterations,
      testMemorySize,
      testTagLength,
    );
    const resultHEX = uint8ArrayToHex(result);
    expect(resultHEX).toBe('53b7d7e24871060915166e96148bab3f6c9ff2a713eb2705e4ff19159aa7ebfb');
  });

  it('should generate different salt each time', async () => {
    const testSalt1 = uint8ArrayToHex(sampleSalt());
    const testSalt2 = uint8ArrayToHex(sampleSalt());
    expect(testSalt1).not.toBe(testSalt2);
  });

  it('should give the same result for the same password and salt', async () => {
    const result1 = await getKeyFromPasswordAndSalt(testPassword, testSalt);
    const result2 = await getKeyFromPasswordAndSalt(testPassword, testSalt);
    expect(result1).toStrictEqual(result2);
  });

  it('should throw an error if no password is given', async () => {
    await expect(getKeyFromPassword('')).rejects.toThrowError(/Failed to derive key from password/);
  });

  it('should throw an error if no salt or password given', async () => {
    await expect(getKeyFromPasswordAndSalt(testPassword, new Uint8Array())).rejects.toThrowError(
      /Failed to derive key from password and salt/,
    );
    await expect(getKeyFromPasswordAndSalt('', testSalt)).rejects.toThrowError(
      /Failed to derive key from password and salt/,
    );
  });
});
