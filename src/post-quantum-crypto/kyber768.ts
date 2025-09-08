import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

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
    return ml_kem768.keygen(seed);
  } catch (error) {
    throw new Error('Failed to generate Kyber keys', { cause: error });
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
    return ml_kem768.encapsulate(publicKey);
  } catch (error) {
    throw new Error('Failed to encapsulate', { cause: error });
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
    return ml_kem768.decapsulate(cipherText, secretKey);
  } catch (error) {
    throw new Error('Failed to decapsulate', { cause: error });
  }
}
