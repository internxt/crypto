import { PublicKeys } from '../types';
import { base64ToPublicKey } from '../email-crypto/converters';
import { getRecipientsPublicKeysFromServer } from './api-keys';

/**
 * Obtains the recipient public keys from the server
 *
 * @param email - The recipients' emails
 * @returns The list of recipients' public keys
 */
export async function getRecipientsPublicKeys(emails: string[]): Promise<PublicKeys[]> {
  try {
    const publicKeysBase64: string[] = await getRecipientsPublicKeysFromServer(emails);
    const result: PublicKeys[] = [];
    for (const keyBase64 of publicKeysBase64) {
      const publicKeys = await base64ToPublicKey(keyBase64);
      result.push(publicKeys);
    }
    return result;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to get recipients public keys: ${errorMessage}`);
  }
}
