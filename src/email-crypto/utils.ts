import { concatBytes } from '@noble/hashes/utils.js';
import { EmailPublicParameters } from '../types';
import { UTF8ToUint8, uuidToBytes } from '../utils';
import { userToBytes, recipientsToBytes } from './converters';

/**
 * Creates an auxilary string from public fields of the email.
 *
 * @param params - The email public parameters.
 * @returns The resulting auxilary string
 */
export function getAux(params: EmailPublicParameters): Uint8Array {
  try {
    const { subject, replyToEmailID, sender, recipient, recipients } = params;
    const subjectBytes = UTF8ToUint8(subject);
    const replyBytes = replyToEmailID ? uuidToBytes(replyToEmailID) : new Uint8Array();
    const senderBytes = userToBytes(sender);
    const recipientBytes = userToBytes(recipient);
    const recipientsBytes = recipients ? recipientsToBytes(recipients) : new Uint8Array();

    const aux = concatBytes(subjectBytes, replyBytes, senderBytes, recipientBytes, recipientsBytes);

    return aux;
  } catch (error) {
    throw new Error('Failed to create aux', { cause: error });
  }
}

/**
 * Creates an auxilary string from public fields of the email (except for subject field).
 *
 * @param params - The email public parameters.
 * @returns The resulting auxilary string
 */
export function getAuxWithoutSubject(params: EmailPublicParameters): Uint8Array {
  try {
    const { replyToEmailID, sender, recipient, recipients } = params;
    const replyBytes = replyToEmailID ? uuidToBytes(replyToEmailID) : new Uint8Array();
    const senderBytes = userToBytes(sender);
    const recipientBytes = userToBytes(recipient);
    const recipientsBytes = recipients ? recipientsToBytes(recipients) : new Uint8Array();

    const aux = concatBytes(replyBytes, senderBytes, recipientBytes, recipientsBytes);

    return aux;
  } catch (error) {
    throw new Error('Failed to create aux without subject', { cause: error });
  }
}
