import { genHybridKeys } from '../hybrid-crypto';
import { HybridKeyPair } from '../types';

/**
 * Generates public and private keys for email encryption.
 *
 * @returns The user's private and public keys
 */
export async function generateEmailKeys(): Promise<HybridKeyPair> {
  return genHybridKeys();
}
