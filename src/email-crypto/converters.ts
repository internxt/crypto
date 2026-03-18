import { UTF8ToUint8 } from '../utils';
import { User, Email } from '../types';
import { concatBytes } from '@noble/hashes/utils.js';

/**
 * Converts a Users into a Uint8Array.
 *
 * @param user - The user.
 * @returns The Uint8Array representation of the user.
 */
export function userToBytes(user: User): Uint8Array {
  try {
    const json = JSON.stringify(user);
    return UTF8ToUint8(json);
  } catch (error) {
    throw new Error('Failed to convert User to bytes', { cause: error });
  }
}

/**
 * Converts an array of Users into a Uint8Array.
 *
 * @param recipients - The array of Users.
 * @returns The Uint8Array representation of the array of Users.
 */
export function recipientsToBytes(recipients: User[]): Uint8Array {
  try {
    const array = recipients.map((user) => userToBytes(user));
    return concatBytes(...array);
  } catch (error) {
    throw new Error('Failed to convert recipients to bytes', { cause: error });
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
