import { describe, expect, expectTypeOf, it, beforeAll } from 'vitest';
import {
  openDatabase,
  encryptAndStoreManyEmail,
  encryptAndStoreEmail,
  getEmailCount,
  getAndDecryptAllEmails,
  MailDB,
  closeDatabase,
  deleteDatabase,
  getAndDecryptEmail,
  deleteEmail,
  getAllEmailsSortedOldestFirst,
  deleteOldestEmails,
  getAllEmailsSortedNewestFirst,
  getEmailBatch,
  enforceMaxEmailNumber,
  deriveIndexKey,
} from '../../src/email-search';
import { Email } from '../../src/types';
import { genSymmetricCryptoKey, genSymmetricKey } from '../../src/symmetric-crypto';
import { generateTestEmails, generateTestEmail } from './helper';

describe('Test searchable database functions', async () => {
  const emailNumber = 5;
  const emails: Email[] = generateTestEmails(emailNumber);
  const userID = 'mock ID';
  const key = await genSymmetricCryptoKey();

  beforeAll(async () => {
    await deleteDatabase(userID);
  });

  it('should sucesfully open the database, add emails and get all emails', async () => {
    const db = await openDatabase(userID);
    expectTypeOf(db).toEqualTypeOf<MailDB>();
    await encryptAndStoreManyEmail(emails, key, db);
    const count = await getEmailCount(db);
    expect(count).toBe(emailNumber);
    const gotEmails = await getAndDecryptAllEmails(key, db);
    expect(emails).toEqual(expect.arrayContaining(gotEmails));

    closeDatabase(db);
  });

  it('should re-open database and ensure it still has emails', async () => {
    const db = await openDatabase(userID);
    const count = await getEmailCount(db);
    expect(count).toBe(emailNumber);
    closeDatabase(db);
  });

  it('should sucessfully get specific email', async () => {
    const db = await openDatabase(userID);
    const id = emails[0].params.id;
    const email = await getAndDecryptEmail(id, key, db);
    expect(email).toStrictEqual(emails[0]);
    closeDatabase(db);
  });

  it('should re-open database and ensure it still has emails', async () => {
    const db = await openDatabase(userID);
    const count = await getEmailCount(db);
    expect(count).toBe(emailNumber);
    closeDatabase(db);
  });

  it('should sucessfully delete specific email', async () => {
    const db = await openDatabase(userID);
    const id = emails[0].params.id;
    await deleteEmail(id, db);
    const count = await getEmailCount(db);
    expect(count).toBe(emailNumber - 1);
    const gotEmails = await getAndDecryptAllEmails(key, db);
    expect(gotEmails.some((email) => email.params.id === id)).toBe(false);
    closeDatabase(db);
  });

  it('should sucessfully add one email to existing database', async () => {
    const db = await openDatabase(userID);
    const email = generateTestEmail();
    await encryptAndStoreEmail(email, key, db);
    const count = await getEmailCount(db);
    expect(count).toBe(emailNumber);
    const gotEmails = await getAndDecryptAllEmails(key, db);
    expect(gotEmails).toContainEqual(email);
    closeDatabase(db);
  });

  it('should not change database if the same email added again', async () => {
    const db = await openDatabase(userID);
    const email = generateTestEmail();
    await encryptAndStoreEmail(email, key, db);
    const count = await getEmailCount(db);
    expect(count).toBe(emailNumber + 1);
    await encryptAndStoreEmail(email, key, db);
    const new_count = await getEmailCount(db);
    expect(new_count).toBe(emailNumber + 1);
    closeDatabase(db);
  });

  it('should sucessfully delete oldest emails ', async () => {
    const number = 2;
    const db = await openDatabase(userID);
    const emails = await getAllEmailsSortedOldestFirst(db, key);
    await deleteOldestEmails(number, db);
    const all_emails = await getAndDecryptAllEmails(key, db);
    for (let i = 0; i < number; i++) {
      expect(all_emails).not.toContainEqual(emails[i]);
    }

    closeDatabase(db);
  });

  it('should sucessfully get email batch', async () => {
    const batchSize = 3;
    const db = await openDatabase(userID);
    const allEmails = await getAllEmailsSortedNewestFirst(db, key);
    const batchedEmails: Email[] = [];
    let nextCursor: IDBValidKey | undefined;

    do {
      const result = await getEmailBatch(db, key, batchSize, nextCursor);
      batchedEmails.push(...result.emails);
      nextCursor = result.nextCursor;
      expect(result.emails.length).toBeLessThanOrEqual(batchSize);
    } while (nextCursor);

    expect(batchedEmails.length).toBe(allEmails.length);
    expect(batchedEmails).toStrictEqual(allEmails);

    closeDatabase(db);
  });

  it('should sucessfully set max email number ', async () => {
    const number = 7;
    const db = await openDatabase(userID);
    const emails = generateTestEmails(number);
    await encryptAndStoreManyEmail(emails, key, db);
    const count = await getEmailCount(db);
    expect(count).not.toBe(number);
    await enforceMaxEmailNumber(db, number);
    const new_count = await getEmailCount(db);
    expect(new_count).toBe(number);

    closeDatabase(db);
  });

  it('after deling the database and opening it, email count is 0 ', async () => {
    await deleteDatabase(userID);
    const db = await openDatabase(userID);
    const count = await getEmailCount(db);
    expect(count).toBe(0);
    closeDatabase(db);
  });

  it('derive index key should work', async () => {
    const baseKey = await genSymmetricKey();
    const new_key = await deriveIndexKey(baseKey);

    expect(new_key).toBeInstanceOf(CryptoKey);
  });
});
