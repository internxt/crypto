import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';

export function generateKyberKeys(seed?: Uint8Array): {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
} {
  return ml_kem1024.keygen(seed);
}

export function encapsulateKyber(publicKey: Uint8Array): {
  cipherText: Uint8Array;
  sharedSecret: Uint8Array;
} {
  try {
    if (!publicKey?.length) {
      throw Error('No public key given');
    }
    return ml_kem1024.encapsulate(publicKey);
  } catch (error) {
    throw new Error(`Failed to encapsulate: ${error}`);
  }
}

export function decapsulateKyber(cipherText: Uint8Array, secretKey: Uint8Array): Uint8Array {
  return ml_kem1024.decapsulate(cipherText, secretKey);
}
