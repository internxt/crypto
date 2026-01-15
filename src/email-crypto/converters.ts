import { UTF8ToUint8, uint8ToUTF8 } from '../utils';
import { EmailBody, User, Email } from '../types';
import { concatBytes } from '@noble/hashes/utils.js';

export function userToBytes(user: User): Uint8Array {
  try {
    const json = JSON.stringify(user);
    return UTF8ToUint8(json);
  } catch (error) {
    throw new Error('Failed to convert User to bytes', { cause: error });
  }
}

export function recipientsToBytes(recipients: User[]): Uint8Array {
  try {
    const array = recipients.map((user) => userToBytes(user));
    return concatBytes(...array);
  } catch (error) {
    throw new Error('Failed to convert recipients to bytes', { cause: error });
  }
}

/**
 * Converts an EmailBody type into a Uint8Array array.
 *
 * @param body - The email body.
 * @returns The Uint8Array array representation of the EmailBody type.
 */
export function emailBodyToBinary(body: EmailBody): Uint8Array {
  try {
    const json = JSON.stringify(body);
    return UTF8ToUint8(json);
  } catch (error) {
    throw new Error('Failed to convert EmailBody to Uint8Array', { cause: error });
  }
}

/**
 * Converts an Uint8Array array into EmailBody type.
 *
 * @param array - The Uint8Array array.
 * @returns The EmailBody type representation of the Uint8Array.
 */
export function binaryToEmailBody(array: Uint8Array): EmailBody {
  try {
    const json = uint8ToUTF8(array);
    const email: EmailBody = JSON.parse(json);
    return email;
  } catch (error) {
    throw new Error('Failed to convert Uint8Array to EmailBody', { cause: error });
  }
}

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
