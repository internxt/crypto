import { HybridEncryptedEmail, PwdProtectedEmail } from '../types';
import { hybridEncyptedEmailToBase64, pwdProtectedEmailToBase64 } from '../email-crypto/converters';
import { sendEmail } from './api-send';

/**
 * Sends a hybridly encrypted email to a particular recipient recipient
 *
 * @param encryptedEmail - The hybridly encrypted email
 * @returns The server reply
 */
export async function sendHybridEmail(encryptedEmail: HybridEncryptedEmail) {
  try {
    if (encryptedEmail.recipientID !== encryptedEmail.params.recipient.id) {
      throw new Error('Email is encrypted for another recipient');
    }
    const body = hybridEncyptedEmailToBase64(encryptedEmail);
    await sendEmail(body, encryptedEmail.params);
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
export async function sendPwdProtectedEmail(protectedEmail: PwdProtectedEmail) {
  try {
    const body = pwdProtectedEmailToBase64(protectedEmail);
    await sendEmail(body, protectedEmail.params);
  } catch (error) {
    throw new Error('Failed to email to the recipient', { cause: error });
  }
}
