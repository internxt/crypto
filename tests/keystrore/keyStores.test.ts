import { describe, expect, it } from "vitest";
import {
  createEncryptionKeystore,
  createIdentityKeystore,
  openEncryptionKeystore,
  openIdentityKeystore,
  createRecoveryKeystore,
  openRecoveryKeystore,
} from "../../src/keystore/keyStores";
import { v4 as uuidv4 } from "uuid";
import { EncryptionKeys, IdentityKeys } from "../../src/utils/types";
import { generateSymmetricCryptoKey } from "../../src/core/symmetric";

describe("Test key store functions", () => {
  it("should successfully create and open identity keystore", async () => {
    const userID = uuidv4();
    const nonce = 14;
    const keys: IdentityKeys = {
      userPublicKey: "user public key",
      userPrivateKey: "user private key",
      serverPublicKey: "server public key",
    };
    const secretKey = await generateSymmetricCryptoKey();
    const { ciphertext, iv } = await createIdentityKeystore(
      secretKey,
      nonce,
      keys,
      userID,
    );
    const result = await openIdentityKeystore(
      secretKey,
      iv,
      ciphertext,
      userID,
    );

    expect(result).toStrictEqual(keys);
  });

  it("should successfully create and open encryption keystore", async () => {
    const userID = uuidv4();
    const nonce = 14;
    const keys: EncryptionKeys = {
      userPublicKey: "user public key",
      userPrivateKey: "user private key",
      userPrivateKyberKey: "user private kyber key",
      userPublicKyberKey: "user public kyber key",
    };
    const secretKey = await generateSymmetricCryptoKey();
    const { ciphertext, iv } = await createEncryptionKeystore(
      secretKey,
      nonce,
      keys,
      userID,
    );
    const result = await openEncryptionKeystore(
      secretKey,
      iv,
      ciphertext,
      userID,
    );

    expect(result).toStrictEqual(keys);
  });

  it("should successfully create and open recovery keystore", async () => {
    const userID = uuidv4();
    const nonce = 14;
    const keys: EncryptionKeys = {
      userPublicKey: "user public key",
      userPrivateKey: "user private key",
      userPrivateKyberKey: "user private kyber key",
      userPublicKyberKey: "user public kyber key",
    };
    const recoveryKey = await generateSymmetricCryptoKey();
    const { ciphertext, iv } = await createRecoveryKeystore(
      recoveryKey,
      nonce,
      keys,
      userID,
    );
    const result = await openRecoveryKeystore(
      recoveryKey,
      iv,
      ciphertext,
      userID,
    );

    expect(result).toStrictEqual(keys);
  });
});
