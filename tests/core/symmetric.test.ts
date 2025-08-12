import { describe, expect, it } from "vitest";
import {
  createIV,
  encryptSymmetrically,
  decryptSymmetrically,
  generateSymmetricCryptoKey,
} from "../../src/core/symmetric";
import {
  AES_ALGORITHM,
  AES_KEY_BIT_LENGTH,
  IV_LENGTH,
  NONCE_LENGTH,
} from "../../src/utils/constants";

describe("Test symmetric functions", () => {
  it("should generate iv as expected", async () => {
    const n = 4;
    const iv = createIV(n);
    const view = new DataView(iv.buffer, 12, 4);
    const number = view.getUint32(0, false);

    expect(number).toBe(n);
    expect(iv.length).toBe(IV_LENGTH);

    const iv_new = createIV(n);
    expect(iv).not.toEqual(iv_new);
  });

  it("should handle the modules bigger than NONE_LENGTH", async () => {
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

  it("should sucessfully generate keys", async () => {
    const key = await generateSymmetricCryptoKey();

    expect(key).toBeInstanceOf(CryptoKey);
    expect(key.type).toBe("secret");
    expect(key.extractable).toBeTruthy();
    expect(key.usages).toContain("encrypt");
    expect(key.usages).toContain("decrypt");

    const alg = key.algorithm as AesKeyAlgorithm;
    expect(alg.name).toBe(AES_ALGORITHM);
    expect(alg.length).toBe(AES_KEY_BIT_LENGTH);
  });

  it("should sucessfully encrypt and decrypt", async () => {
    const key = await generateSymmetricCryptoKey();
    const nonce = 1;
    const message = new Uint8Array([12, 42, 32, 44, 88, 89, 99, 100]);
    const aux = "additional data";

    const { ciphertext, iv } = await encryptSymmetrically(
      key,
      nonce,
      message,
      aux,
    );
    const result = await decryptSymmetrically(key, iv, ciphertext, aux);

    expect(result).toStrictEqual(message);
  });
});
