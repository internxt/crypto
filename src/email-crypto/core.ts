import { EmailBody, Email, SymmetricCiphertext, HybridEncryptedEmail, PwdProtectedEmail } from '../utils';
import { genSymmetricCryptoKey, encryptSymmetrically, decryptSymmetrically } from '../symmetric-crypto';
import { emailBodyToBinary, binaryToEmailBody } from './converters';

export function getAux(email: HybridEncryptedEmail | PwdProtectedEmail | Email): string {
  try {
    const { subject, emailChainLength, sender, recipients } = email;
    const aux = JSON.stringify({ subject, emailChainLength, sender, recipients });
    return aux;
  } catch (error) {
    throw new Error(`Cannot create aux: ${error}`);
  }
}

export async function encryptEmailSymmetrically(
  email: Email,
): Promise<{ encEmail: SymmetricCiphertext; encryptionKey: CryptoKey }> {
  try {
    const aux = getAux(email);
    const encryptionKey = await genSymmetricCryptoKey();
    const emailBody = email.body;
    const binaryEmail = emailBodyToBinary(emailBody);
    const { ciphertext, iv } = await encryptSymmetrically(encryptionKey, email.emailChainLength, binaryEmail, aux);
    const encEmail: SymmetricCiphertext = { ciphertext, iv };
    return { encEmail, encryptionKey };
  } catch (error) {
    return Promise.reject(new Error(`Cannot encrypt email: ${error}`));
  }
}

export async function decryptEmailSymmetrically(
  encryptedEmail: HybridEncryptedEmail | PwdProtectedEmail,
  encryptionKey: CryptoKey,
): Promise<EmailBody> {
  try {
    const aux = getAux(encryptedEmail);
    const emailCiphertext: SymmetricCiphertext = encryptedEmail.ciphertext;
    const binaryEmail = await decryptSymmetrically(encryptionKey, emailCiphertext, aux);
    const email = binaryToEmailBody(binaryEmail);
    return email;
  } catch (error) {
    return Promise.reject(new Error(`Cannot decrypt email: ${error}`));
  }
}
