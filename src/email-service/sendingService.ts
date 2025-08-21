import { HybridEncryptedEmail, PwdProtectedEmail, User } from '../utils';
import { encHybridKeyToBase64, pwdProtectedKeyToBase64 } from '../email-crypto/converters';
import { ciphertextToBase64 } from '../symmetric-crypto';
import { sendEmail } from './coreSend';

export async function sendHybridEmailToMultipleRecipients(encryptedEmails: HybridEncryptedEmail[]) {
  try {
    for (const encEmail of encryptedEmails) {
      await sendHybridEmail(encEmail);
    }
  } catch (error) {
    throw new Error('Failed to email to multiple recipients:', error);
  }
}

export async function sendHybridEmail(encEmail: HybridEncryptedEmail) {
  try {
    const encText = ciphertextToBase64(encEmail.ciphertext);
    const encKey = encHybridKeyToBase64(encEmail.encryptedKey);
    const body = JSON.stringify({ encText, encKey });
    await sendEmail(encEmail.subject, body, encEmail.sender, encEmail.encryptedFor);
  } catch (error) {
    throw new Error(`Failed to email to the recipient ${encEmail.encryptedFor.name}:`, error);
  }
}

export async function sendPwdProtectedEmailToMultipleRecipients(pwdProtectedEmail: PwdProtectedEmail) {
  try {
    for (const recipient of pwdProtectedEmail.recipients) {
      await sendPwdProtectedEmail(pwdProtectedEmail, recipient);
    }
  } catch (error) {
    throw new Error('Failed to email to multiple recipients:', error);
  }
}

export async function sendPwdProtectedEmail(encEmail: PwdProtectedEmail, recipient: User) {
  try {
    const encText = ciphertextToBase64(encEmail.ciphertext);
    const encKey = pwdProtectedKeyToBase64(encEmail.encryptedKey);
    const body = JSON.stringify({ encText, encKey });
    await sendEmail(encEmail.subject, body, encEmail.sender, recipient);
  } catch (error) {
    throw new Error(`Failed to email to the recipient ${recipient}:`, error);
  }
}
