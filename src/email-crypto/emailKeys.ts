import { genHybridKeys } from '../hybrid-crypto';
import { HybridKeyPair } from '../types';
import { deriveKeyFromMnemonic } from '../derive-key';
import { CONTEXT_DATABASE, CONTEXT_DRAFT } from '../constants';

/**
 * Generates public and private keys for email encryption.
 *
 * @returns The user's private and public keys
 */
export async function generateEmailKeys(): Promise<HybridKeyPair> {
  return genHybridKeys();
}

/**
 * Derives database encryption key for the given user
 *
 * @param mnemonic - The user's mnemonic (machine-generated with secure PRNG)
 * @returns The symmetric key for protecting database
 */
export const deriveDatabaseKey = async (mnemonic: string): Promise<Uint8Array> => {
  return deriveKeyFromMnemonic(mnemonic, CONTEXT_DATABASE);
};

/**
 * Derives email draft encryption key for the given user
 *
 * @param mnemonic - The user's mnemonic (machine-generated with secure PRNG)
 * @returns The symmetric key for protecting email drafts
 */
export const deriveEmailDraftKey = async (mnemonic: string): Promise<Uint8Array> => {
  return deriveKeyFromMnemonic(mnemonic, CONTEXT_DRAFT);
};
