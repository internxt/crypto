import { HybridEncryptedEmail, PwdProtectedEmail, User } from '../utils';
import { encHybridKeyToBase64, pwdProtectedKeyToBase64 } from '../email-crypto/converters';
import { ciphertextToBase64 } from '../symmetric-crypto';
import { sendEmail } from './api-send';

/**
 * Sends a list of hybridly encrypted emails to all intended recipients
 *
 * @param encryptedEmails - The list of hybridly encrypted emails
 * @returns The server reply
 */
export async function sendHybridEmailToMultipleRecipients(encryptedEmails: HybridEncryptedEmail[]) {
  try {
    for (const encEmail of encryptedEmails) {
      await sendHybridEmail(encEmail);
    }
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to email to multiple recipients: ${errorMessage}`);
  }
}

/**
 * Sends a hybridly encrypted email to a particular recipient recipient
 *
 * @param encryptedEmail - The hybridly encrypted email
 * @returns The server reply
 */
export async function sendHybridEmail(encryptedEmail: HybridEncryptedEmail) {
  try {
    const encText = ciphertextToBase64(encryptedEmail.ciphertext);
    const encKey = encHybridKeyToBase64(encryptedEmail.encryptedKey);
    const body = JSON.stringify({ encText, encKey });
    await sendEmail(encryptedEmail.subject, body, encryptedEmail.sender, encryptedEmail.encryptedFor);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to email to the recipient ${encryptedEmail.encryptedFor.name}: ${errorMessage}`);
  }
}

/**
 * Sends a password-protected email to all its intended recipients
 *
 * @param pwdProtectedEmail - The password protected email
 * @returns The server reply
 */
export async function sendPwdProtectedEmailToMultipleRecipients(pwdProtectedEmail: PwdProtectedEmail) {
  try {
    for (const recipient of pwdProtectedEmail.recipients) {
      await sendPwdProtectedEmail(pwdProtectedEmail, recipient);
    }
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to email to multiple recipients: ${errorMessage}`);
  }
}

/**
 * Sends a password-protected email to a particular recipient
 *
 * @param pwdProtectedEmail - The password protected email
 * @param recipient - The email recipient
 * @returns The server reply
 */
export async function sendPwdProtectedEmail(encEmail: PwdProtectedEmail, recipient: User) {
  try {
    const encText = ciphertextToBase64(encEmail.ciphertext);
    const encKey = pwdProtectedKeyToBase64(encEmail.encryptedKey);
    const body = JSON.stringify({ encText, encKey });
    await sendEmail(encEmail.subject, body, encEmail.sender, recipient);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to email to the recipient ${recipient}: ${errorMessage}`);
  }
}
