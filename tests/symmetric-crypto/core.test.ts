import { describe, expect, it } from 'vitest';
import { createNISTbasedIV } from '../../src/symmetric-crypto/core';
import { genSymmetricCryptoKey, encryptSymmetrically } from '../../src/symmetric-crypto';
import { base64ToCiphertext, ciphertextToBase64 } from '../../src/utils';
import { SymmetricCiphertext } from '../../src/types';
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

  it('should convert ciphertext to base64 and back', async () => {
    const key = await genSymmetricCryptoKey();
    const message = new Uint8Array([12, 42, 32, 44, 88, 89, 99, 100]);
    const aux = 'additional data';
    const enc = await encryptSymmetrically(key, message, aux);

    const base64 = await ciphertextToBase64(enc);
    const result = await base64ToCiphertext(base64);

    expect(enc).toStrictEqual(result);
  });

  it('should throw an error if cannot convert ciphertext to base64', async () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const bad_ciphertext: any = {};
    bad_ciphertext.self = bad_ciphertext;
    expect(() => ciphertextToBase64(bad_ciphertext as SymmetricCiphertext)).toThrowError(
      /Failed to convert ciphertext to base64/,
    );
  });

  it('should throw an error if cannot convert base64 to ciphertext', async () => {
    const bad_base64 = 'bad base 64';
    expect(() => base64ToCiphertext(bad_base64)).toThrowError(/Failed to convert base64 to ciphertext/);
  });
});
