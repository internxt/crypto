import { EmailPublicParameters, HybridEncryptedEmail, PwdProtectedEmail } from '../types';
import { hybridEncyptedEmailToBase64, pwdProtectedEmailToBase64 } from '../email-crypto/converters';
import { sendEmail } from './api-send';

/**
 * Sends a hybridly encrypted email to a particular recipient recipient
 *
 * @param encryptedEmail - The hybridly encrypted email
 * @returns The server reply
 */
export async function sendHybridEmail(encryptedEmail: HybridEncryptedEmail, params: EmailPublicParameters) {
  try {
    if (encryptedEmail.recipientID !== params.recipient.id) {
      throw new Error('Email is encrypted for another recipient');
    }
    const body = hybridEncyptedEmailToBase64(encryptedEmail);
    await sendEmail(body, params);
  } catch (error) {
    throw new Error('Failed to email to the recipient', { cause: error });
  }
}

/**
 * Sends a password-protected email to a particular recipient
 *
 * @param protectedEmail - The password protected email
 * @param recipient - The email recipient
 * @returns The server reply
 */
export async function sendPwdProtectedEmail(protectedEmail: PwdProtectedEmail, params: EmailPublicParameters) {
  try {
    const body = pwdProtectedEmailToBase64(protectedEmail);
    await sendEmail(body, params);
  } catch (error) {
    throw new Error('Failed to email to the recipient', { cause: error });
  }
}
