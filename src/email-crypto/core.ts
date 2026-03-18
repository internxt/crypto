import { HybridEncKey, PwdProtectedKey, EmailBody, EmailBodyEncrypted, Email, EmailPublicParameters } from '../types';
import { encryptSymmetrically, decryptSymmetrically, genSymmetricKey } from '../symmetric-crypto';
import { encapsulateHybrid, decapsulateHybrid } from '../hybrid-crypto';
import { wrapKey, unwrapKey } from '../key-wrapper';
import { getKeyFromPassword, getKeyFromPasswordAndSalt } from '../derive-key';
import { UTF8ToUint8, base64ToUint8Array, uint8ArrayToBase64, uint8ToUTF8, uuidToBytes } from '../utils';
import { getAux } from './utils';

/**
 * Symmetrically encrypts email body.
 *
 * @param email - The email to encrypt.
 * @param isSubjectEncrypted -  Indicates if the email subject field was encrypted
 * @returns The resulting encrypted email body, updated public parameters (with encrypted subject if it was encrypted) and symmetric key used for encryption
 */
export async function encryptEmailBody(
  email: Email,
  isSubjectEncrypted: boolean,
): Promise<{
  enc: EmailBodyEncrypted;
  params: EmailPublicParameters;
  encryptionKey: Uint8Array;
}> {
  try {
    const aux = getAux(email.params, isSubjectEncrypted);

    let enc: EmailBodyEncrypted;
    let encryptionKey: Uint8Array;
    let params = email.params;

    if (isSubjectEncrypted) {
      const result = await encryptEmailContentAndSubjectSymmetrically(email.body, email.params.subject, aux, email.id);
      enc = result.enc;
      encryptionKey = result.encryptionKey;
      params = { ...email.params, subject: result.encSubject };
    } else {
      const result = await encryptEmailContentSymmetrically(email.body, aux, email.id);
      enc = result.enc;
      encryptionKey = result.encryptionKey;
    }

    return { encryptionKey, enc, params };
  } catch (error) {
    throw new Error('Failed to encrypt email body', { cause: error });
  }
}

/**
 * Decrypts symmetrically encrypted email body.
 *
 * @param enc - The email body to decrypt.
 * @param encParams - The email paramaters.
 * @param encryptionKey - The symmetric key to decrypt the email.
 * @param isSubjectEncrypted -  Indicates if the email subject field was encrypted
 * @returns The resulting decrypted email body and updated public parameters (with decrypted subject if it was encrypted)
 */
export async function decryptEmailBody(
  enc: EmailBodyEncrypted,
  encParams: EmailPublicParameters,
  encryptionKey: Uint8Array,
  isSubjectEncrypted: boolean,
): Promise<{
  params: EmailPublicParameters;
  body: EmailBody;
}> {
  try {
    const aux = getAux(encParams, isSubjectEncrypted);
    let body: EmailBody;
    let params = encParams;
    if (isSubjectEncrypted) {
      const result = await decryptEmailAndSubjectSymmetrically(encryptionKey, aux, encParams.subject, enc);
      body = result.body;
      params = { ...encParams, subject: result.subject };
    } else {
      body = await decryptEmailSymmetrically(encryptionKey, aux, enc);
    }

    return { body, params };
  } catch (error) {
    throw new Error('Failed to encrypt email body', { cause: error });
  }
}

/**
 * Symmetrically encrypts an email with a randomly sampled key.
 *
 * @param email - The email to encrypt.
 * @param aux - The auxiliary data (e.g., email ID or timestamp) for AEAD.
 * @param emailID - The unique identifier of the email.
 * @returns The resulting ciphertext and the used symmetric key
 */
export async function encryptEmailContentSymmetrically(
  email: EmailBody,
  aux: Uint8Array,
  emailID: string,
): Promise<{ enc: EmailBodyEncrypted; encryptionKey: Uint8Array }> {
  try {
    if (!email.text) {
      throw new Error('Invalid input');
    }
    const encryptionKey = genSymmetricKey();
    const enc = await encryptEmailContentSymmetricallyWithKey(email, encryptionKey, aux, emailID);
    return { enc, encryptionKey };
  } catch (error) {
    throw new Error('Failed to symmetrically encrypt email', { cause: error });
  }
}

/**
 * Symmetrically encrypts an email with a randomly sampled key.
 *
 * @param email - The email to encrypt.
 * @param subject - The email subject to encrypt.
 * @param aux - The auxiliary data (e.g., email ID or timestamp) for AEAD.
 * @param emailID - The unique identifier of the email.
 * @returns The resulting ciphertext and the used symmetric key
 */
export async function encryptEmailContentAndSubjectSymmetrically(
  email: EmailBody,
  subject: string,
  aux: Uint8Array,
  emailID: string,
): Promise<{ enc: EmailBodyEncrypted; encSubject: string; encryptionKey: Uint8Array }> {
  try {
    if (!subject || !email.text) {
      throw new Error('Invalid input');
    }
    const encryptionKey = genSymmetricKey();
    const enc = await encryptEmailContentSymmetricallyWithKey(email, encryptionKey, aux, emailID);
    const subjectBuff = UTF8ToUint8(subject);
    const subjectEnc = await encryptSymmetrically(encryptionKey, subjectBuff, aux);
    const encSubject = uint8ArrayToBase64(subjectEnc);
    return { enc, encSubject, encryptionKey };
  } catch (error) {
    throw new Error('Failed to symmetrically encrypt email and subject', { cause: error });
  }
}

/**
 * Decrypts symmetrically encrypted email and its subject.
 *
 * @param encryptionKey - The symmetric key for encryption.
 * @param aux - The auxiliary data (e.g., email ID or timestamp) for AEAD.
 * @param encSubject - The encrypted email subject.
 * @param enc - The encrypted email body.
 * @returns The resulting encrypted emailBody
 */
export async function decryptEmailAndSubjectSymmetrically(
  encryptionKey: Uint8Array,
  aux: Uint8Array,
  encSubject: string,
  enc: EmailBodyEncrypted,
): Promise<{ body: EmailBody; subject: string }> {
  try {
    const array = base64ToUint8Array(encSubject);
    const subjectArray = await decryptSymmetrically(encryptionKey, array, aux);
    const body = await decryptEmailSymmetrically(encryptionKey, aux, enc);
    const subject = uint8ToUTF8(subjectArray);
    return { body, subject };
  } catch (error) {
    throw new Error('Failed to symmetrically decrypt email and subject', { cause: error });
  }
}

/**
 * Symmetrically encrypts an email with a randomly sampled key.
 *
 * @param emailBody - The email body to encrypt.
 * @param encryptionKey - The symmetric key for encryption.
 * @param aux - The auxiliary data (e.g., email ID or timestamp) for AEAD.
 * @param emailID - The unique identifier of the email.
 * @returns The resulting encrypted emailBody
 */
export async function encryptEmailContentSymmetricallyWithKey(
  emailBody: EmailBody,
  encryptionKey: Uint8Array,
  aux: Uint8Array,
  emailID: string,
): Promise<EmailBodyEncrypted> {
  try {
    const freeField = uuidToBytes(emailID);
    const text = UTF8ToUint8(emailBody.text);
    const encryptedText = await encryptSymmetrically(encryptionKey, text, aux, freeField);
    const encText = uint8ArrayToBase64(encryptedText);
    const result: EmailBodyEncrypted = { encText };

    if (emailBody.attachments) {
      const encryptedAttachements = await encryptEmailAttachements(emailBody.attachments, encryptionKey, aux, emailID);
      result.encAttachments = encryptedAttachements?.map(uint8ArrayToBase64);
    }
    return result;
  } catch (error) {
    throw new Error('Failed to symmetrically encrypt email with the given key', { cause: error });
  }
}

/**
 * Symmetrically encrypts email attachements.
 *
 * @param attachments - The attachments.
 * @param encryptionKey - The symmetric key.
 * @param aux - The auxiliary data (e.g., email ID or timestamp) for AEAD.
 * @param emailID - The unique identifier of the email.
 * @returns The decrypted email attackements
 */
async function encryptEmailAttachements(
  attachments: string[],
  encryptionKey: Uint8Array,
  aux: Uint8Array,
  emailID: string,
): Promise<Uint8Array[]> {
  try {
    const freeField = uuidToBytes(emailID);
    const encryptedAttachments = await Promise.all(
      attachments.map((attachment) => {
        const binaryAttachment = UTF8ToUint8(attachment);
        return encryptSymmetrically(encryptionKey, binaryAttachment, aux, freeField);
      }),
    );
    return encryptedAttachments;
  } catch (error) {
    throw new Error('Failed to symmetrically encrypt email attachements', { cause: error });
  }
}

/**
 * Decrypts symmetrically encrypted email attachements.
 *
 * @param encryptedAttachments - The encrypted attachments.
 * @param encryptionKey - The symmetric key.
 * @param aux - The auxiliary data (e.g., email ID or timestamp) for AEAD.
 * @returns The decrypted email attackements
 */
async function decryptEmailAttachements(
  encryptedAttachments: Uint8Array[],
  encryptionKey: Uint8Array,
  aux: Uint8Array,
): Promise<Uint8Array[]> {
  try {
    const decryptedAttachments = await Promise.all(
      encryptedAttachments.map((attachment) => {
        return decryptSymmetrically(encryptionKey, attachment, aux);
      }),
    );
    return decryptedAttachments;
  } catch (error) {
    throw new Error('Failed to symmetrically decrypt email attachements', { cause: error });
  }
}

/**
 * Decrypts symmetrically encrypted email.
 *
 * @param encryptionKey - The symmetric key.
 * @param aux -  The auxiliary data (e.g., email ID or timestamp) for AEAD.
 * @param enc - The email body to decrypt.
 * @returns The decrypted email
 */
export async function decryptEmailSymmetrically(
  encryptionKey: Uint8Array,
  aux: Uint8Array,
  enc: EmailBodyEncrypted,
): Promise<EmailBody> {
  try {
    const cipher = base64ToUint8Array(enc.encText);
    const textArray = await decryptSymmetrically(encryptionKey, cipher, aux);
    const text = uint8ToUTF8(textArray);
    const result: EmailBody = { text };

    if (enc.encAttachments) {
      const encAttachements = enc.encAttachments?.map(base64ToUint8Array);
      const attachmentsArray = await decryptEmailAttachements(encAttachements, encryptionKey, aux);
      result.attachments = attachmentsArray?.map((att) => uint8ToUTF8(att));
    }
    return result;
  } catch (error) {
    throw new Error('Failed to symmetrically decrypt email', { cause: error });
  }
}

/**
 * Encrypts the email symmetric key using hybrid encryption.
 *
 * @param emailEncryptionKey - The symmetric key used for email encryption.
 * @param recipientPublicHybridKey - The public key of the recipient.
 * @returns The encrypted email symmetric key
 */
export async function encryptKeysHybrid(
  emailEncryptionKey: Uint8Array,
  recipientPublicHybridKey: Uint8Array,
): Promise<HybridEncKey> {
  try {
    const { cipherText, sharedSecret } = encapsulateHybrid(recipientPublicHybridKey);
    const encryptedKey = await wrapKey(emailEncryptionKey, sharedSecret);
    const encryptedKeyBase64 = uint8ArrayToBase64(encryptedKey);
    const kyberCiphertextBase64 = uint8ArrayToBase64(cipherText);

    return { encryptedKey: encryptedKeyBase64, kyberCiphertext: kyberCiphertextBase64 };
  } catch (error) {
    throw new Error('Failed to encrypt email key using hybrid encryption', { cause: error });
  }
}

/**
 * Decrypts the email symmetric key encrypted via hybrid encryption.
 *
 * @param encryptedKey - The encrypted email key.
 * @param recipientPrivateKey - The private key of the recipient.
 * @returns The email encryption key
 */
export async function decryptKeysHybrid(
  encryptedKey: HybridEncKey,
  recipientPrivateKey: Uint8Array,
): Promise<Uint8Array> {
  try {
    const kyberCiphertext = base64ToUint8Array(encryptedKey.kyberCiphertext);
    const encKey = base64ToUint8Array(encryptedKey.encryptedKey);
    const sharedSecret = decapsulateHybrid(kyberCiphertext, recipientPrivateKey);
    const encryptionKey = await unwrapKey(encKey, sharedSecret);
    return encryptionKey;
  } catch (error) {
    throw new Error('Failed to decrypt email key encrypted via hybrid encryption', { cause: error });
  }
}

/**
 * Password-protects the email symmetric key.
 *
 * @param emailEncryptionKey - The symmetric key used for email encryption.
 * @param password - The secret password for key protection.
 * @returns The password-protected email symmetric key
 */
export async function passwordProtectKey(emailEncryptionKey: Uint8Array, password: string): Promise<PwdProtectedKey> {
  try {
    const { key, salt } = await getKeyFromPassword(password);
    const encryptedKey = await wrapKey(emailEncryptionKey, key);
    const saltStr = uint8ArrayToBase64(salt);
    const encryptedKeyStr = uint8ArrayToBase64(encryptedKey);
    return { encryptedKey: encryptedKeyStr, salt: saltStr };
  } catch (error) {
    throw new Error('Failed to password-protect email key', { cause: error });
  }
}

/**
 * Removes passoword-protection and exposes the email symmetric key.
 *
 * @param emailEncryptionKey -  The password-protected email key.
 * @param password - The secret password for key protection.
 * @returns The email encryption key
 */
export async function removePasswordProtection(
  emailEncryptionKey: PwdProtectedKey,
  password: string,
): Promise<Uint8Array> {
  try {
    const salt = base64ToUint8Array(emailEncryptionKey.salt);
    const encryptedKey = base64ToUint8Array(emailEncryptionKey.encryptedKey);
    const key = await getKeyFromPasswordAndSalt(password, salt);
    const encryptionKey = await unwrapKey(encryptedKey, key);
    return encryptionKey;
  } catch (error) {
    throw new Error('Failed to remove password-protection from email key', { cause: error });
  }
}
