import { UTF8ToUint8 } from '../utils';
import { Email } from '../types';

/**
 * Converts an Email type into a Uint8Array array.
 *
 * @param email - The email.
 * @returns The Uint8Array array representation of the Email type.
 */
export function emailToBinary(email: Email): Uint8Array {
  try {
    const json = JSON.stringify(email);
    return UTF8ToUint8(json);
  } catch (error) {
    throw new Error('Failed to convert EmailBody to Uint8Array', { cause: error });
  }
}
