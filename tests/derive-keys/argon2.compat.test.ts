import { describe, expect, it } from 'vitest';
import { argon2 as webArgon2 } from '../../src/derive-password/core';
import { argon2 as nativeArgon2 } from '../../src/derive-password/core.native';
import { randomBytes } from '@noble/hashes/utils.js';
import { ARGON2ID_SALT_BYTE_LENGTH } from '../../src/constants';

describe('core.ts vs core.native.ts parity', () => {
  it('produces identical key for the same password and salt', async () => {
    const password = 'correct horse battery staple';
    const salt = randomBytes(ARGON2ID_SALT_BYTE_LENGTH);

    const webKey = await webArgon2(password, salt);
    const nativeKey = await nativeArgon2(password, salt);

    expect(webKey).toStrictEqual(nativeKey);
  });

  it('produces different keys for different salts, consistently on both sides', async () => {
    const password = 'correct horse battery staple';
    const saltA = randomBytes(ARGON2ID_SALT_BYTE_LENGTH);
    const saltB = randomBytes(ARGON2ID_SALT_BYTE_LENGTH);

    const webKeyA = await webArgon2(password, saltA);
    const webKeyB = await webArgon2(password, saltB);
    const nativeKeyA = await nativeArgon2(password, saltA);
    const nativeKeyB = await nativeArgon2(password, saltB);

    expect(webKeyA).not.toStrictEqual(webKeyB);
    expect(nativeKeyA).not.toStrictEqual(nativeKeyB);
    expect(webKeyA).toStrictEqual(nativeKeyA);
    expect(webKeyB).toStrictEqual(nativeKeyB);
  });

  it('exposes the same public API surface', () => {
    expect(Object.keys(webArgon2 as object).sort()).toStrictEqual(Object.keys(nativeArgon2 as object).sort());
  });
});