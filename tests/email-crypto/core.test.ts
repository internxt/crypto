import { describe, expect, it } from 'vitest';
import { Email, EmailAndSubject } from '../../src/types';
import {
  decryptEmail,
  encryptEmail,
  deriveDatabaseKey,
  deriveEmailDraftKey,
  encryptEmailAndSubject,
  decryptEmailAndSubject,
} from '../../src/email-crypto';
import { genMnemonic } from '../../src/utils';
import { genSymmetricKey } from '../../src/symmetric-crypto';
import { AES_KEY_BYTE_LENGTH } from '../../src/constants';
import { EmailSymmetricDecryptionError, InvalidInputEmail } from '../../src/email-crypto/errors';

describe('Test email crypto functions', () => {
  const email: Email = {
    text: 'test email',
    preview: 'email preview',
    attachmentsSessionKey: new Uint8Array([1,2,3,4,5,6,7,8]),
  };

  const emailAndSubject: EmailAndSubject = {
    text: 'test email text',
    subject: 'test email subject',
    preview: 'email preview',
    attachmentsSessionKey: new Uint8Array([1,2,3,4,5,6,7,8]),
  };

  const aux = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);

  it('should encrypt and decrypt email', async () => {
    const { encEmail, encryptionKey } = await encryptEmail(email, aux);
    const result = await decryptEmail(encEmail, encryptionKey, aux);
    expect(result).toEqual(email);
  });

  it('should encrypt and decrypt email with subject', async () => {
    const { encEmail, encryptionKey } = await encryptEmailAndSubject(emailAndSubject, aux);
    const result = await decryptEmailAndSubject(encEmail, encryptionKey, aux);
    expect(result).toEqual(emailAndSubject);
  });

  it('should throw an error if decryption fails', async () => {
    const { encEmail, encryptionKey } = await encryptEmail(email, aux);
    const badEncryptionKey = await genSymmetricKey();
    await expect(decryptEmail(encEmail, badEncryptionKey, aux)).rejects.toThrow(EmailSymmetricDecryptionError);

    const badAux = new Uint8Array([4, 5, 6, 7, 8]);
    await expect(decryptEmail(encEmail, encryptionKey, badAux)).rejects.toThrow(EmailSymmetricDecryptionError);
  });

  it('should throw an error if decryption fails', async () => {
    const { encEmail, encryptionKey } = await encryptEmailAndSubject(emailAndSubject, aux);
    const badEncryptionKey = await genSymmetricKey();
    await expect(decryptEmailAndSubject(encEmail, badEncryptionKey, aux)).rejects.toThrow(
      EmailSymmetricDecryptionError,
    );

    const badAux = new Uint8Array([4, 5, 6, 7, 8]);
    await expect(decryptEmailAndSubject(encEmail, encryptionKey, badAux)).rejects.toThrow(
      EmailSymmetricDecryptionError,
    );
  });

  it('should throw an error if cannot encrypt', async () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const badEmail: any = {};
    badEmail.self = badEmail;
    await expect(encryptEmail(badEmail, aux)).rejects.toThrow(InvalidInputEmail);
    await expect(encryptEmailAndSubject(badEmail, aux)).rejects.toThrow(InvalidInputEmail);
  });

  it('should derive symmetric key for database encryption', async () => {
    const mnemonic = genMnemonic();
    const key = await deriveDatabaseKey(mnemonic);
    expect(key.length).toBe(AES_KEY_BYTE_LENGTH);
    const key2 = await deriveDatabaseKey(mnemonic);
    expect(key2).toStrictEqual(key);
  });

  it('should derive symmetric key for email draft encryption', async () => {
    const mnemonic = genMnemonic();
    const key = await deriveEmailDraftKey(mnemonic);
    expect(key.length).toBe(AES_KEY_BYTE_LENGTH);
    const key2 = await deriveEmailDraftKey(mnemonic);
    expect(key2).toStrictEqual(key);
  });

  it('should derive symmetric key for email draft encryption', async () => {
    const mnemonic = genMnemonic();
    const keyDatabase = await deriveDatabaseKey(mnemonic);
    const keyDraft = await deriveEmailDraftKey(mnemonic);
    expect(keyDatabase.length).toBe(keyDraft.length);
    expect(keyDraft).not.toStrictEqual(keyDatabase);
  });
});
