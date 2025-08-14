import { HybridEncryptedEmail, PwdProtectedEmail, User } from '../utils/types';
import { emailCiphertextToBase64, encHybridKeyToBase64, pwdProtectedKeyToBase64 } from './utils';
import { sendEncryptedEmail } from './api';

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
    const encText = emailCiphertextToBase64(encEmail.ciphertext);
    const encKey = encHybridKeyToBase64(encEmail.encryptedKey);
    await sendEncryptedEmail(encEmail.subject, encText, encKey, encEmail.sender, encEmail.encryptedFor);
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
    const encText = emailCiphertextToBase64(encEmail.ciphertext);
    const encKey = pwdProtectedKeyToBase64(encEmail.encryptedKey);
    await sendEncryptedEmail(subject, encText, encKey, sender, recipient);
  } catch (error) {
    console.error(`Failed to email to the recipient ${recipient}:`, error);
  }
}
