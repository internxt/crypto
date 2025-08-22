import { ml_kem512 } from '@noble/post-quantum/ml-kem.js';

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

export function decapsulateKyber(cipherText: Uint8Array, secretKey: Uint8Array): Uint8Array {
  try {
    return ml_kem512.decapsulate(cipherText, secretKey);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to decapsulate: ${errorMessage}`);
  }
}
