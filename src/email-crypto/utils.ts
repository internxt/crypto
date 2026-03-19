import { concatBytes } from '@noble/hashes/utils.js';
import { UTF8ToUint8 } from '../utils';

/**
 * Creates an auxiliary string for the email.
 *
 * @param senderEmail - The email of the sender
 * @param recipientEmail - The email of the recipient
 * @returns The resulting auxiliary string
 */
export function getAux(senderEmail: string, recipientEmail: string): Uint8Array {
  try {
    const senderBytes = UTF8ToUint8(senderEmail);
    const recipientBytes = UTF8ToUint8(recipientEmail);
    return concatBytes(senderBytes, recipientBytes);
  } catch (error) {
    throw new Error('Failed to create aux', { cause: error });
  }
}
