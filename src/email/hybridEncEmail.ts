import { deriveSecretKey } from '../asymmetric/ecc';
import { deriveWrappingKey, wrapKey, unwrapKey } from '../keyWrappers/aesWrapper';
import { encapsulateKyber, decapsulateKyber } from '../post-quantum/kyber768';
import { Email, HybridEncKey, PublicKeys, HybridEncryptedEmail } from '../utils/types';
import { encryptEmailSymmetrically, decryptEmailSymmetrically } from './utils';

export async function encryptEmailHybrid(
  recipientPublicKeys: PublicKeys,
  senderPrivateKey: CryptoKey,
  email: Email,
): Promise<HybridEncryptedEmail> {
  try {
    const { encEmail: ciphertext, encryptionKey } = await encryptEmailSymmetrically(email);
    const encryptedKey = await encryptKeysHybrid(encryptionKey, recipientPublicKeys, senderPrivateKey);
    const result: HybridEncryptedEmail = {
      recipients: email.recipients,
      encryptedFor: recipientPublicKeys.user,
      sender: email.sender,
      subject: email.subject,
      emailChainLength: email.emailChainLength,
      ciphertext,
      encryptedKey,
    };

    return result;
  } catch (error) {
    return Promise.reject(new Error('Could not encrypt email with hybrid encryption', error));
  }
}

export async function encryptEmailHybridForMultipleRecipients(
  recipientsPublicKeys: PublicKeys[],
  senderPrivateKey: CryptoKey,
  email: Email,
): Promise<HybridEncryptedEmail[]> {
  try {
    const { encEmail: ciphertext, encryptionKey } = await encryptEmailSymmetrically(email);

    const encryptedEmails: HybridEncryptedEmail[] = [];
    for (const keys of recipientsPublicKeys) {
      const encryptedKey = await encryptKeysHybrid(encryptionKey, keys, senderPrivateKey);
      const result: HybridEncryptedEmail = {
        recipients: email.recipients,
        sender: email.sender,
        encryptedFor: keys.user,
        subject: email.subject,
        emailChainLength: email.emailChainLength,
        ciphertext,
        encryptedKey,
      };
      encryptedEmails.push(result);
    }

    return encryptedEmails;
  } catch (error) {
    return Promise.reject(new Error('Could not encrypt email to multiple recipients with hybrid encryption', error));
  }
}

export async function encryptKeysHybrid(
  encryptionKey: CryptoKey,
  recipientPublicKey: PublicKeys,
  userPrivateKey: CryptoKey,
): Promise<HybridEncKey> {
  try {
    const eccSecret = await deriveSecretKey(recipientPublicKey.eccPublicKey, userPrivateKey);
    const { cipherText: kyberCiphertext, sharedSecret: kyberSecret } = encapsulateKyber(
      recipientPublicKey.kyberPublicKey,
    );
    const wrappingKey = await deriveWrappingKey(eccSecret, kyberSecret);
    const encryptedKey = await wrapKey(encryptionKey, wrappingKey);
    return { encryptedKey, kyberCiphertext };
  } catch (error) {
    return Promise.reject(new Error('Could not encrypt keys with hybrid encryption', error));
  }
}

export async function decryptEmailHybrid(
  senderPublicKey: CryptoKey,
  recipientPrivateKey: CryptoKey,
  recipientPrivateKeyKyber: Uint8Array,
  encryptedEmail: HybridEncryptedEmail,
) {
  try {
    const eccSecret = await deriveSecretKey(senderPublicKey, recipientPrivateKey);
    const encKey: HybridEncKey = encryptedEmail.encryptedKey;
    const kyberSecret = decapsulateKyber(encKey.kyberCiphertext, recipientPrivateKeyKyber);
    const wrappingKey = await deriveWrappingKey(eccSecret, kyberSecret);
    const encryptionKey = await unwrapKey(encKey.encryptedKey, wrappingKey);
    const email = await decryptEmailSymmetrically(encryptedEmail, encryptionKey);

    return email;
  } catch (error) {
    return Promise.reject(new Error('Could not decrypt emails with hybrid encryption', error));
  }
}
