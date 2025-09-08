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
} from '../../src/email-search';
import { Email } from '../../src/types';
import { genSymmetricCryptoKey } from '../../src/symmetric-crypto';
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
    const userID = 'mock ID';
    const db = await openDatabase(userID);
    const count = await getEmailCount(db);
    expect(count).toBe(emailNumber);
    closeDatabase(db);
  });

  it('should sucessfully get specific email', async () => {
    const userID = 'mock ID';
    const db = await openDatabase(userID);
    const id = emails[0].params.id;
    const email = await getAndDecryptEmail(id, key, db);
    expect(email).toStrictEqual(emails[0]);
    closeDatabase(db);
  });

  it('should re-open database and ensure it still has emails', async () => {
    const userID = 'mock ID';
    const db = await openDatabase(userID);
    const count = await getEmailCount(db);
    expect(count).toBe(emailNumber);
    closeDatabase(db);
  });

  it('should sucessfully delete specific email', async () => {
    const userID = 'mock ID';
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
    const userID = 'mock ID';
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
    const userID = 'mock ID';
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

  it('after deling the database and opening it, email count is 0 ', async () => {
    const userID = 'mock ID';
    await deleteDatabase(userID);
    const db = await openDatabase(userID);
    const count = await getEmailCount(db);
    expect(count).toBe(0);
    closeDatabase(db);
  });
});
