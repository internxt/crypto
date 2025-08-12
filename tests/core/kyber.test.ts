import { describe, expect, it } from "vitest";
import {
  generateKyberKeys,
  encapsulateKyber,
  decapsulateKyber,
} from "../../src/core/kyber";
import {
  KYBER_PUBLIC_KEY_LENGTH,
  KYBER_SECRET_KEY_LENGTH,
  KYBER_SEED_LENGTH,
} from "../../src/utils/constants";

describe("Test kyber functions", () => {
  it("should generate keys sucessfully", async () => {
    const keys = generateKyberKeys();

    expect(keys).toHaveProperty("publicKey");
    expect(keys).toHaveProperty("secretKey");
    expect(keys.publicKey.length).toBe(KYBER_PUBLIC_KEY_LENGTH);
    expect(keys.secretKey.length).toBe(KYBER_SECRET_KEY_LENGTH);
  });

  it("should generate identical keys for identical seeds", async () => {
    const seed = new Uint8Array(KYBER_SEED_LENGTH);
    window.crypto.getRandomValues(seed);
    const keys1 = generateKyberKeys(seed);
    const keys2 = generateKyberKeys(seed);

    expect(keys1).toStrictEqual(keys2);
  });
  it("should generate different keys for different seeds", async () => {
    const seed1 = new Uint8Array(KYBER_SEED_LENGTH);
    window.crypto.getRandomValues(seed1);
    const keys1 = generateKyberKeys(seed1);

    const seed2 = new Uint8Array(KYBER_SEED_LENGTH);
    window.crypto.getRandomValues(seed2);
    const keys2 = generateKyberKeys(seed2);

    expect(keys1).not.toStrictEqual(keys2);
  });

  it("should sucessfully encapsulate and decapsulate", async () => {
    const keys = generateKyberKeys();
    const { cipherText, sharedSecret } = encapsulateKyber(keys.publicKey);
    const result = decapsulateKyber(cipherText, keys.secretKey);

    expect(result).toStrictEqual(sharedSecret);
  });
});
