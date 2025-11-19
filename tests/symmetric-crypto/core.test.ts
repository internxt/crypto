import { describe, expect, it } from 'vitest';
import { createNISTbasedIV } from '../../src/symmetric-crypto/core';
import { getBytesFromString } from '../../src/hash';

describe('Test symmetric functions', () => {
  it('should generate iv as expected', async () => {
    const freeField = '4';
    const iv = createNISTbasedIV(freeField);
    const number = iv.slice(12);

    const hash = getBytesFromString(4, freeField);

    expect(number).toStrictEqual(hash);
    expect(iv.length).toBe(16);

    const iv_new = createNISTbasedIV(freeField);
    expect(iv).not.toEqual(iv_new);

    const iv_empry_free_field = createNISTbasedIV();
    expect((await iv_empry_free_field).length).toEqual(16);
  });
});
