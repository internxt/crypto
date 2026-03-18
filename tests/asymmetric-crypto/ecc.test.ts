import { describe, expect, it } from 'vitest';
import { generateEccKeys, deriveSecretKey } from '../../src/asymmetric-crypto';

describe('Test ecc functions', () => {
  it('should generate elliptic curves key pair', async () => {
    const keyPair = await generateEccKeys();
    expect(keyPair.publicKey).toBeInstanceOf(Uint8Array);
    expect(keyPair.secretKey).toBeInstanceOf(Uint8Array);
  });

  it('should derive the same keys for Bob and Alice', async () => {
    const keysAlice = await generateEccKeys();
    const keysBob = await generateEccKeys();

    const resultAlice = await deriveSecretKey(keysBob.secretKey, keysAlice.publicKey);
    const resultBob = await deriveSecretKey(keysAlice.secretKey, keysBob.publicKey);

    expect(resultAlice).toStrictEqual(resultBob);
  });

  it('should derive different keys for Bob and Alice and Alice and Eve', async () => {
    const keysAlice = await generateEccKeys();
    const keysBob = await generateEccKeys();
    const keysEve = await generateEccKeys();

    const resultAliceEve = await deriveSecretKey(keysEve.secretKey, keysAlice.publicKey);
    const resultAliceBob = await deriveSecretKey(keysBob.secretKey, keysAlice.publicKey);

    expect(resultAliceBob).not.toStrictEqual(resultAliceEve);
  });

  it('should throw an error if cannot derive', async () => {
    const keysAlice = await generateEccKeys();

    await expect(deriveSecretKey(keysAlice.secretKey, new Uint8Array())).rejects.toThrowError(
      /Failed to derive elliptic curve secret key/,
    );
  });
});
