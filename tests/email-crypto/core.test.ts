import { describe, expect, it } from 'vitest';
import { EmailBody, EmailBodyAndSubject } from '../../src/types';
import {
  decryptEmailBody,
  encryptEmailBody,
  deriveDatabaseKey,
  deriveEmailDraftKey,
  encryptEmailBodyAndSubject,
  decryptEmailBodyAndSubject,
} from '../../src/email-crypto';
import { genMnemonic } from '../../src/utils';
import { genSymmetricKey } from '../../src/symmetric-crypto';
import { AES_KEY_BYTE_LENGTH } from '../../src/constants';
import { EmailSymmetricDecryptionError, InvalidInputEmail } from '../../src/email-crypto/errors';

describe('Test email crypto functions', () => {
  const emailBody: EmailBody = {
    text: 'test body',
  };

  const emailBodyAndSubject: EmailBodyAndSubject = {
    text: 'test body',
    subject: 'test subject',
  };

  const aux = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);

  it('should encrypt and decrypt email', async () => {
    const { encEmailBody, encryptionKey } = await encryptEmailBody(emailBody, aux);
    const result = await decryptEmailBody(encEmailBody, encryptionKey, aux);
    expect(result).toEqual(emailBody);
  });

  it('should encrypt and decrypt email with subject', async () => {
    const { encEmailBody, encryptionKey } = await encryptEmailBodyAndSubject(emailBodyAndSubject, aux);
    const result = await decryptEmailBodyAndSubject(encEmailBody, encryptionKey, aux);
    expect(result).toEqual(emailBodyAndSubject);
  });

  it('should throw an error if decryption fails', async () => {
    const { encEmailBody, encryptionKey } = await encryptEmailBody(emailBody, aux);
    const badEncryptionKey = await genSymmetricKey();
    await expect(decryptEmailBody(encEmailBody, badEncryptionKey, aux)).rejects.toThrow(EmailSymmetricDecryptionError);

    const badAux = new Uint8Array([4, 5, 6, 7, 8]);
    await expect(decryptEmailBody(encEmailBody, encryptionKey, badAux)).rejects.toThrow(EmailSymmetricDecryptionError);
  });

  it('should throw an error if decryption fails', async () => {
    const { encEmailBody, encryptionKey } = await encryptEmailBodyAndSubject(emailBodyAndSubject, aux);
    const badEncryptionKey = await genSymmetricKey();
    await expect(decryptEmailBodyAndSubject(encEmailBody, badEncryptionKey, aux)).rejects.toThrow(
      EmailSymmetricDecryptionError,
    );

    const badAux = new Uint8Array([4, 5, 6, 7, 8]);
    await expect(decryptEmailBodyAndSubject(encEmailBody, encryptionKey, badAux)).rejects.toThrow(
      EmailSymmetricDecryptionError,
    );
  });

  it('should throw an error if cannot encrypt', async () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const badEmail: any = {};
    badEmail.self = badEmail;
    await expect(encryptEmailBody(badEmail, aux)).rejects.toThrow(InvalidInputEmail);
    await expect(encryptEmailBodyAndSubject(badEmail, aux)).rejects.toThrow(InvalidInputEmail);
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
