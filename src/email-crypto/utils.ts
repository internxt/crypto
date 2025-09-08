import { EmailPublicParameters } from '../types';
import { v4 as uuidv4 } from 'uuid';

/**
 * Creates an auxilary string from public fields of the email.
 *
 * @param params - The email public parameters.
 * @returns The resulting auxilary string
 */
export function getAux(params: EmailPublicParameters): string {
  try {
    const { subject, replyToEmailID, sender, recipients } = params;
    const aux = JSON.stringify({ subject, replyToEmailID, sender, recipients });
    return aux;
  } catch (error) {
    throw new Error('Failed to create aux', { cause: error });
  }
}

/**
 * Creates a random email ID.
 *
 * @returns The resulting auxilary string
 */
export function generateEmailID(): string {
  return uuidv4();
}
