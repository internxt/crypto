import { x25519 } from '@noble/curves/webcrypto.js';

/**
 * Derives secret key from the other user's public key and own private key
 *
 * @param aliceSecretKey - The secret key of the user deriving the shared secret key
 * @param bobPublicKey - The public key of the other user
 * @returns The derived secret key bits
 */
export async function deriveSecretKey(aliceSecretKey: Uint8Array, bobPublicKey: Uint8Array): Promise<Uint8Array> {
  try {
    return await x25519.getSharedSecret(aliceSecretKey, bobPublicKey);
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
  return x25519.keygen();
}
