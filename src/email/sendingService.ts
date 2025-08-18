import { HybridEncryptedEmail, PwdProtectedEmail, User } from '../utils/types';
import { encHybridKeyToBase64, pwdProtectedKeyToBase64 } from './converters';
import { ciphertextToBase64 } from '../symmetric/utils';
import { sendEmail } from './api';

export async function sendHybridEmailToMultipleRecipients(encryptedEmails: HybridEncryptedEmail[]) {
  try {
    for (const encEmail of encryptedEmails) {
      await sendHybridEmail(encEmail);
    }
  } catch (error) {
    console.error('Failed to email to multiple recipients:', error);
  }
}

export async function sendHybridEmail(encEmail: HybridEncryptedEmail) {
  try {
    const encText = ciphertextToBase64(encEmail.ciphertext);
    const encKey = encHybridKeyToBase64(encEmail.encryptedKey);
    const body = JSON.stringify({ encText, encKey });
    await sendEmail(encEmail.subject, body, encEmail.sender, encEmail.encryptedFor);
  } catch (error) {
    console.error(`Failed to email to the recipient ${encEmail.encryptedFor}:`, error);
  }
}

export async function sendPwdProtectedEmailToMultipleRecipients(pwdProtectedEmail: PwdProtectedEmail) {
  try {
    for (const recipient of pwdProtectedEmail.recipients) {
      await sendPwdProtectedEmail(pwdProtectedEmail, pwdProtectedEmail.subject, pwdProtectedEmail.sender, recipient);
    }
  } catch (error) {
    console.error('Failed to email to multiple recipients:', error);
  }
}

export async function sendPwdProtectedEmail(
  encEmail: PwdProtectedEmail,
  subject: string,
  sender: User,
  recipient: User,
) {
  try {
    const encText = ciphertextToBase64(encEmail.ciphertext);
    const encKey = pwdProtectedKeyToBase64(encEmail.encryptedKey);
    const body = JSON.stringify({ encText, encKey });
    await sendEmail(subject, body, sender, recipient);
  } catch (error) {
    console.error(`Failed to email to the recipient ${recipient}:`, error);
  }
}
