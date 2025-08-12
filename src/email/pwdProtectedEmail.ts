import { importWrappingKey, unwrapKey, wrapKey } from '../core/keyWrapper';
import { generateSymmetricCryptoKey, encryptSymmetrically, decryptSymmetrically } from '../core/symmetric';
import { getKeyFromPassword, getKeyFromPasswordAndSalt } from '../keys/deriveKeysFromPwd';
import { Email, EncryptedEmailPwd } from '../utils/types';
import { emailToBinary, binaryToEmail } from './converters';

export async function encryptPwdProtectedEmail(
  sharedSecret: string,
  emailsInChain: number,
  email: Email,
  aux: string,
): Promise<EncryptedEmailPwd> {
  const encryptionKey = await generateSymmetricCryptoKey();
  const binaryEmail = emailToBinary(email);
  const { ciphertext: encryptedEmail, iv } = await encryptSymmetrically(encryptionKey, emailsInChain, binaryEmail, aux);

  const { key, salt } = await getKeyFromPassword(sharedSecret);
  console.log('argon2 test', key.length, salt.length);
  const wrappingKey = await importWrappingKey(key);
  console.log('imported everything');
  const encryptedKey = await wrapKey(encryptionKey, wrappingKey);

  return {
    encryptedEmail,
    encryptedKey,
    iv,
    salt,
  };
}

export async function decryptPwdProtectedEmail(sharedSecret: string, encryptedEmail: EncryptedEmailPwd, aux: string) {
  const key = await getKeyFromPasswordAndSalt(sharedSecret, encryptedEmail.salt);
  const wrappingKey = await importWrappingKey(key);
  const encryptionKey = await unwrapKey(encryptedEmail.encryptedKey, wrappingKey);
  const decryptedBits = await decryptSymmetrically(
    encryptionKey,
    encryptedEmail.iv,
    encryptedEmail.encryptedEmail,
    aux,
  );
  const result = binaryToEmail(decryptedBits);
  return result;
}
