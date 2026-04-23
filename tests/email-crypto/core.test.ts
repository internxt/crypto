import { describe, expect, it } from 'vitest';
import { EmailBody } from '../../src/types';
import { decryptEmailBody, encryptEmailBody, deriveDatabaseKey, deriveEmailDraftKey } from '../../src/email-crypto';
import { generateUuid, genMnemonic } from '../../src/utils';
import { genSymmetricKey } from '../../src/symmetric-crypto';
import { AES_KEY_BYTE_LENGTH } from '../../src/constants';

describe('Test email crypto functions', () => {
  const emailBody: EmailBody = {
    text: 'test body',
    subject: 'test subject',
  };

  const aux = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);

  it('should generate email id', async () => {
    const result1 = generateUuid();
    const result2 = generateUuid();
    expect(result1).not.toEqual(result2);
    expect(result1).toHaveLength(36);
  });

  it('should encrypt and decrypt email', async () => {
    const { encEmailBody, encryptionKey } = await encryptEmailBody(emailBody, aux);
    const result = await decryptEmailBody(encEmailBody, encryptionKey, aux);
    expect(result).toEqual(emailBody);
  });

  it('should throw an error if decryption fails', async () => {
    const { encEmailBody, encryptionKey } = await encryptEmailBody(emailBody, aux);
    const badEncryptionKey = await genSymmetricKey();
    await expect(decryptEmailBody(encEmailBody, badEncryptionKey, aux)).rejects.toThrowError(
      /Failed to symmetrically decrypt email body/,
    );

    const badAux = new Uint8Array([4, 5, 6, 7, 8]);
    await expect(decryptEmailBody(encEmailBody, encryptionKey, badAux)).rejects.toThrowError(
      /Failed to symmetrically decrypt email body/,
    );
  });

  it('should throw an error if cannot encrypt', async () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const badEmail: any = {};
    badEmail.self = badEmail;
    await expect(encryptEmailBody(badEmail, aux)).rejects.toThrowError(/Failed to symmetrically encrypt email body/);
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
