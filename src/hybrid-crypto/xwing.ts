import { XWing as hybridCipher } from '@noble/post-quantum/hybrid.js';
import { HybridKeyPair } from '../types';

export function genHybridKeys(seed?: Uint8Array): HybridKeyPair {
  return hybridCipher.keygen(seed);
}

export function encapsulateHybrid(publicKey: Uint8Array): { cipherText: Uint8Array; sharedSecret: Uint8Array } {
  return hybridCipher.encapsulate(publicKey);
}

export function decapsulateHybrid(cipherText: Uint8Array, secretKey: Uint8Array): Uint8Array {
  return hybridCipher.decapsulate(cipherText, secretKey);
}
