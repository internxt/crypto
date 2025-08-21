import { describe, expect, it } from 'vitest';
import { createIV, base64ToCiphertext, ciphertextToBase64 } from '../../src/symmetric/utils';
import { IV_LENGTH, NONCE_LENGTH } from '../../src/utils/constants';
import { genSymmetricCryptoKey, encryptSymmetrically } from '../../src/symmetric';
import { SymmetricCiphertext } from '../../src/utils/types';

describe('Test symmetric functions', () => {
  it('should generate iv as expected', async () => {
    const n = 4;
    const iv = createIV(n);
    const view = new DataView(iv.buffer, 12, 4);
    const number = view.getUint32(0, false);

    expect(number).toBe(n);
    expect(iv.length).toBe(IV_LENGTH);

    const iv_new = createIV(n);
    expect(iv).not.toEqual(iv_new);
  });

  it('should handle the modules bigger than NONE_LENGTH', async () => {
    const n = 4;
    const max_value = Math.pow(2, NONCE_LENGTH * 8);
    const iv = createIV(n + max_value);
    const view = new DataView(iv.buffer, 12, 4);
    const number = view.getUint32(0, false);

    expect(number).toBe(n);
    expect(iv.length).toBe(IV_LENGTH);

    const iv_new = createIV(n);
    expect(iv).not.toEqual(iv_new);
  });

  it('should convert ciphertext to base64 and back', async () => {
    const key = await genSymmetricCryptoKey();
    const nonce = 1;
    const message = new Uint8Array([12, 42, 32, 44, 88, 89, 99, 100]);
    const aux = 'additional data';
    const enc = await encryptSymmetrically(key, nonce, message, aux);

    const base64 = await ciphertextToBase64(enc);
    const result = await base64ToCiphertext(base64);

    expect(enc).toStrictEqual(result);
  });

  it('should throw an error if cannot convert ciphertext to base64', async () => {
    const bad_ciphertext: any = {};
    bad_ciphertext.self = bad_ciphertext;
    expect(() => ciphertextToBase64(bad_ciphertext as SymmetricCiphertext)).toThrowError(
      /Cannot convert ciphertext to base64/,
    );
  });

  it('should throw an error if cannot convert base64 to ciphertext', async () => {
    const bad_base64 = 'bad base 64';
    expect(() => base64ToCiphertext(bad_base64)).toThrowError(/Cannot convert base64 to ciphertext/);
  });
});
