import { concatBytes } from '@noble/hashes/utils.js';
import { EmailPublicParameters } from '../types';
import { UTF8ToUint8, uuidToBytes } from '../utils';
import { userToBytes, recipientsToBytes } from './converters';

/**
 * Creates an auxiliary string from public fields of the email.
 *
 * @param params - The email public parameters.
 * @param isSubjectEncrypted - Indicates if the email subject field should be encrypted
 * @returns The resulting auxiliary string
 */
export function getAux(params: EmailPublicParameters, isSubjectEncrypted: boolean): Uint8Array {
  try {
    const { subject, replyToEmailID, sender, recipient, recipients } = params;
    const replyBytes = replyToEmailID ? uuidToBytes(replyToEmailID) : new Uint8Array();
    const senderBytes = userToBytes(sender);
    const recipientBytes = userToBytes(recipient);
    const recipientsBytes = recipients ? recipientsToBytes(recipients) : new Uint8Array();

    if (isSubjectEncrypted) {
      return concatBytes(replyBytes, senderBytes, recipientBytes, recipientsBytes);
    } else {
      const subjectBytes = UTF8ToUint8(subject);
      return concatBytes(subjectBytes, replyBytes, senderBytes, recipientBytes, recipientsBytes);
    }
  } catch (error) {
    throw new Error('Failed to create aux', { cause: error });
  }
}
