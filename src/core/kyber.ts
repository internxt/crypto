import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";

export function generateKyberKeys(seed?: Uint8Array): {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
} {
  return ml_kem768.keygen(seed);
}

export function encapsulateKyber(publicKey: Uint8Array): {
  cipherText: Uint8Array;
  sharedSecret: Uint8Array;
} {
  return ml_kem768.encapsulate(publicKey);
}

export function decapsulateKyber(
  cipherText: Uint8Array,
  secretKey: Uint8Array,
): Uint8Array {
  return ml_kem768.decapsulate(cipherText, secretKey);
}
