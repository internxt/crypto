import { MediaKeys } from '../types';
import { CONTEXT_RATCHET } from '../constants';
import { deriveSymmetricKeyFromContext } from './deriveKeysFromKey';

/**
 * Ratchets media key.
 * Ratcheting means deriving new key from the old one using a secure key derivation function
 *
 * @param {MediaKeys} key - The input key.
 * @returns {Promise<MediaKeys>} Ratched key.
 */
export async function ratchetMediaKey(key: MediaKeys): Promise<MediaKeys> {
  try {
    const olmKey = await deriveSymmetricKeyFromContext(CONTEXT_RATCHET, key.olmKey);
    const pqKey = await deriveSymmetricKeyFromContext(CONTEXT_RATCHET, key.pqKey);
    const index = key.index + 1;
    const userID = key.userID;
    return { olmKey, pqKey, index, userID };
  } catch (error) {
    throw new Error('Failed to ratchet media key', { cause: error });
  }
}
