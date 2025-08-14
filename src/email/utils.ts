import {
  EmailBody,
  Email,
  PublicKeys,
  PublicKeysBase64,
  symmetricCiphertext,
  HybridEncKey,
  PwdProtectedKey,
  HybridEncryptedEmail,
  PwdProtectedEmail,
} from '../utils/types';
import { Buffer } from 'buffer';
import { genSymmetricCryptoKey, encryptSymmetrically, decryptSymmetrically } from '../symmetric';
import { exportPublicKey, importPublicKey } from '../asymmetric';
import { unwrapKey } from '../keyWrappers';

export function emailBodyToBinary(email: EmailBody): Uint8Array {
  try {
    const json = JSON.stringify(email);
    const buffer = Buffer.from(json);
    return new Uint8Array(buffer);
  } catch (error) {
    throw new Error(`Cannot convert email to Uint8Array: ${error}`);
  }
}

export function binaryToEmailBody(array: Uint8Array): EmailBody {
  try {
    const json = Buffer.from(array).toString('utf-8');
    const email: EmailBody = JSON.parse(json);
    return email;
  } catch (error) {
    throw new Error(`Cannot convert Uint8Array to email: ${error}`);
  }
}

export async function base64ToPublicKey(key: PublicKeysBase64): Promise<PublicKeys> {
  try {
    const eccPublicKeyBytes = Buffer.from(key.eccPublicKey, 'base64');
    const eccPublicKey = await importPublicKey(eccPublicKeyBytes);
    const kyberPublicKey = Buffer.from(key.kyberPublicKey, 'base64');
    return { eccPublicKey, kyberPublicKey, user: key.user };
  } catch (error) {
    throw new Error(`Cannot convert base64 public key to public key: ${error}`);
  }
}

export async function publicKeyToBase64(key: PublicKeys): Promise<PublicKeysBase64> {
  try {
    const eccPublicKeyArray = await exportPublicKey(key.eccPublicKey);
    const eccPublicKey = Buffer.from(eccPublicKeyArray).toString('base64');
    const kyberPublicKey = Buffer.from(key.kyberPublicKey).toString('base64');
    return { eccPublicKey, kyberPublicKey, user: key.user };
  } catch (error) {
    throw new Error(`Cannot convert public key to base64 public key: ${error}`);
  }
}

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
): Promise<{ encEmail: symmetricCiphertext; encryptionKey: CryptoKey }> {
  const aux = getAux(email);
  const encryptionKey = await genSymmetricCryptoKey();
  const emailBody = email.body;
  const binaryEmail = emailBodyToBinary(emailBody);
  const { ciphertext, iv } = await encryptSymmetrically(encryptionKey, email.emailChainLength, binaryEmail, aux);
  const encEmail: symmetricCiphertext = { ciphertext, iv };
  return { encEmail, encryptionKey };
}

export async function decryptEmailSymmetrically(
  encryptedEmail: HybridEncryptedEmail | PwdProtectedEmail,
  wrappingKey: CryptoKey,
  encryptedKey: Uint8Array,
): Promise<EmailBody> {
  const aux = getAux(encryptedEmail);
  const emailCiphertext: symmetricCiphertext = encryptedEmail.ciphertext;

  const encryptionKey = await unwrapKey(encryptedKey, wrappingKey);
  const binaryEmail = await decryptSymmetrically(encryptionKey, emailCiphertext.iv, emailCiphertext.ciphertext, aux);
  const email = binaryToEmailBody(binaryEmail);
  return email;
}

export function emailCiphertextToBase64(emailCipher: symmetricCiphertext): string {
  const json = JSON.stringify(emailCipher);
  const base64 = btoa(json);
  return base64;
}

export function encHybridKeyToBase64(encHybridKey: HybridEncKey): string {
  const json = JSON.stringify(encHybridKey);
  const base64 = btoa(json);
  return base64;
}

export function pwdProtectedKeyToBase64(pwdProtectedKey: PwdProtectedKey): string {
  const json = JSON.stringify(pwdProtectedKey);
  const base64 = btoa(json);
  return base64;
}
