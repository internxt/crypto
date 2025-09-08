import { MediaKeys } from '../types';
import { getBitsFromData } from './blake3';
import { HASH_BIT_LEN, PREFIX_MEDIA_KEY_COMMITMENT } from '../constants';
import { uint8ArrayToHex, mediaKeysToBase64 } from '../utils';

/**
 * Computes commitment to the media keys
 *
 * @param keys - The media keys
 * @returns The resulting commitment string
 */
export async function comitToMediaKey(keys: MediaKeys): Promise<string> {
  try {
    const keysBase64 = mediaKeysToBase64(keys);
    const result = await getBitsFromData(HASH_BIT_LEN, [PREFIX_MEDIA_KEY_COMMITMENT, keysBase64]);
    return uint8ArrayToHex(result);
  } catch (error) {
    throw new Error('Failed to compute commitment to media keys', { cause: error });
  }
}
