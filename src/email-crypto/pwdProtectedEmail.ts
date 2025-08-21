import { importWrappingKey, wrapKey, unwrapKey } from '../key-wrapper';
import { getKeyFromPassword, getKeyFromPasswordAndSalt } from '../derive-key';
import { PwdProtectedEmail, Email, PwdProtectedKey } from '../utils/types';
import { encryptEmailSymmetrically, decryptEmailSymmetrically } from './utils';

export async function createPwdProtectedEmail(sharedSecret: string, email: Email): Promise<PwdProtectedEmail> {
  const { encEmail, encryptionKey } = await encryptEmailSymmetrically(email);

  const { key, salt } = await getKeyFromPassword(sharedSecret);
  const wrappingKey = await importWrappingKey(key);
  const encryptedKey = await wrapKey(encryptionKey, wrappingKey);
  const encKey: PwdProtectedKey = { encryptedKey, salt };
  const result: PwdProtectedEmail = {
    sender: email.sender,
    recipients: email.recipients,
    subject: email.subject,
    emailChainLength: email.emailChainLength,
    ciphertext: encEmail,
    encryptedKey: encKey,
  };
  return result;
}

export async function decryptPwdProtectedEmail(sharedSecret: string, encryptedEmail: PwdProtectedEmail) {
  const encKey = encryptedEmail.encryptedKey;
  const key = await getKeyFromPasswordAndSalt(sharedSecret, encKey.salt);
  const wrappingKey = await importWrappingKey(key);
  const encryptionKey = await unwrapKey(encKey.encryptedKey, wrappingKey);
  const result = await decryptEmailSymmetrically(encryptedEmail, encryptionKey);
  return result;
}
