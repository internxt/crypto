import { x25519 } from '@noble/curves/webcrypto.js';

function asBytes(result: unknown): Uint8Array {
  if (result instanceof Uint8Array) return result;
  throw new Error('Expected raw key bytes, got JWK');
}

/**
 * Derives secret key from the other user's public key and own private key
 *
 * @param aliceSecretKey - The secret key of the user deriving the shared secret key
 * @param bobPublicKey - The public key of the other user
 * @returns The derived secret key bits
 */
export async function deriveSecretKey(aliceSecretKey: Uint8Array, bobPublicKey: Uint8Array): Promise<Uint8Array> {
  try {
    const spkiPublic = asBytes(await x25519.utils.convertPublicKey(bobPublicKey, 'raw', 'spki'));
    const pkcs8Secret = asBytes(await x25519.utils.convertSecretKey(aliceSecretKey, 'raw', 'pkcs8'));
    return await x25519.getSharedSecret(pkcs8Secret, spkiPublic);
  } catch (error) {
    throw new Error('Failed to derive elliptic curve secret key', { cause: error });
  }
}

/**
 * Generates elliptic curve key pair
 *
 * @returns The generated key pair
 */
export async function generateEccKeys(): Promise<{ secretKey: Uint8Array; publicKey: Uint8Array }> {
  const { secretKey, publicKey } = await x25519.keygen();
  return {
    secretKey: asBytes(await x25519.utils.convertSecretKey(secretKey, 'pkcs8', 'raw')),
    publicKey: asBytes(await x25519.utils.convertPublicKey(publicKey, 'spki', 'raw')),
  };
}
