import { ml_kem512 } from '@noble/post-quantum/ml-kem.js';

/**
 * Generates public and secret Kyber keys
 *
 * @param seed - The optional seed
 * @returns The generated Kyber key pair.
 */
export function generateKyberKeys(seed?: Uint8Array): {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
} {
  try {
    return ml_kem512.keygen(seed);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to generate Kyber keys: ${errorMessage}`);
  }
}

/**
 * Generates a shared secret of 256-bits and encapsulates it to the given public key using Kyber algorithms
 *
 * @param publicKey - The public Kyber key
 * @returns The resulting encapsulation and the generated shared secret.
 */
export function encapsulateKyber(publicKey: Uint8Array): {
  cipherText: Uint8Array;
  sharedSecret: Uint8Array;
} {
  try {
    return ml_kem512.encapsulate(publicKey);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to encapsulate: ${errorMessage}`);
  }
}

/**
 * Decapsulates the encapsulated shared secret using Kyber algorithms
 *
 * @param cipherText - The encapsulated key
 * @param secretKey - The private Kyber key
 * @returns The resulting decapsulated shared secret.
 */
export function decapsulateKyber(cipherText: Uint8Array, secretKey: Uint8Array): Uint8Array {
  try {
    return ml_kem512.decapsulate(cipherText, secretKey);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to decapsulate: ${errorMessage}`);
  }
}
