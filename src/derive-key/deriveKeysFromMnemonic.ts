import { mnemonicToBytes } from '../utils';
import { deriveSymmetricKeyFromContext } from './deriveKeysFromKey';

/**
 * Derives encryption key from the user's mnemonic and context string
 *
 * @param mnemonic - The user's mnemonic (machine-generated with secure PRNG)
 * @param context - The context string.
 * The context string should be hardcoded, globally unique, and application-specific.
 * @returns The symmetric key for protecting database
 */
export const deriveKeyFromMnemonic = async (mnemonic: string, context: string): Promise<Uint8Array> => {
  // mnemonic is always machine-generated with secure PRNG, so it is safe to convert it to bytes without additional processing
  const entropy = mnemonicToBytes(mnemonic);
  return deriveSymmetricKeyFromContext(context, entropy);
};
