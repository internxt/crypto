import { describe, expect, it } from 'vitest';
import { generateEccKeys, deriveSecretKey } from '../../src/asymmetric-crypto';

describe('Test ecc functions', () => {
  it('should derive the same keys for Bob and Alice', async () => {
    const keysAlice = await generateEccKeys();
    const keysBob = await generateEccKeys();

    const resultAlice = await deriveSecretKey(keysBob.publicKey, keysAlice.privateKey);
    const resultBob = await deriveSecretKey(keysAlice.publicKey, keysBob.privateKey);

    expect(resultAlice).toStrictEqual(resultBob);
  });

  it('should derive different keys for Bob and Alice and Alice and Eve', async () => {
    const keysAlice = await generateEccKeys();
    const keysBob = await generateEccKeys();
    const keysEve = await generateEccKeys();

    const resultAliceEve = await deriveSecretKey(keysEve.publicKey, keysAlice.privateKey);
    const resultAliceBob = await deriveSecretKey(keysBob.publicKey, keysAlice.privateKey);

    expect(resultAliceBob).not.toStrictEqual(resultAliceEve);
  });

  it('should throw an error if cannot derive', async () => {
    const keysAlice = await generateEccKeys();

    await expect(deriveSecretKey(keysAlice.privateKey, keysAlice.privateKey)).rejects.toThrowError(
      /Failed to derive elliptic curve secret key/,
    );
  });
});
