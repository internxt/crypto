import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import {
  addEmailToCache,
  addEmailsToCache,
  getEmailFromCache,
  deleteEmailFromCache,
  deleteDatabase,
  openDatabase,
  encryptAndStoreManyEmail,
  closeDatabase,
  createCacheFromDB,
  getEmailCount,
} from '../../src/email-search';
import { Email } from '../../src/types';
import { genSymmetricCryptoKey } from '../../src/symmetric-crypto';
import { generateTestEmails, generateTestEmail, getAllEmailSize, getEmailSize } from './helper';
import { MailDB } from '../../src/email-search';

describe('Test mail cache functions', () => {
  beforeAll(async () => {
    await deleteDatabase(userID);
    key = await genSymmetricCryptoKey();
    db = await openDatabase(userID);
    await encryptAndStoreManyEmail(emails, key, db);
  });

  afterAll(async () => {
    closeDatabase(db);
  });

  const emailNumber = 5;
  const emails: Email[] = generateTestEmails(emailNumber);
  const userID = 'mock ID';
  let db: MailDB;
  let key: CryptoKey;

  it('cacheEmailsFromIDB sucessfully reads emails form database', async () => {
    const esCache = await createCacheFromDB(key, db);
    const totalSize = getAllEmailSize(emails);

    const count = await getEmailCount(db);
    expect(count).toBe(emailNumber);

    expect(esCache.esCache.size).toBe(emailNumber);
    expect(esCache.cacheSize).toBe(totalSize);
    expect(esCache.esCache.get(emails[0].id)).toEqual(emails[0]);
  });

  it('addEmailToCache adds an email and updates size', async () => {
    const email = generateTestEmail();
    const esCache = await createCacheFromDB(key, db);
    const sizeBefore = esCache.cacheSize;
    const result = addEmailToCache(email, esCache);
    const diff = esCache.cacheSize - sizeBefore;
    const emailSize = getEmailSize(email);

    expect(result.success).toBe(true);
    expect(diff).toBe(emailSize);
    expect(esCache.esCache.size).toBe(emailNumber + 1);
  });

  it('addEmailToCache will not add the same email twice', async () => {
    const email = generateTestEmail();
    const esCache = await createCacheFromDB(key, db);
    const result = addEmailToCache(email, esCache);
    expect(result.success).toBe(true);

    const sizeBeforeSecondInsert = esCache.esCache.size;
    expect(sizeBeforeSecondInsert).toBe(emailNumber + 1);

    const result_repeated = addEmailToCache(email, esCache);

    expect(result_repeated.success).toBe(false);
    expect(esCache.esCache.size).toBe(sizeBeforeSecondInsert);
  });

  it('addEmailsToCache adds multiple emails', async () => {
    const number = 3;
    const esCache = await createCacheFromDB(key, db);
    const emails = generateTestEmails(number);
    const before = esCache.cacheSize;
    const size_before = esCache.esCache.size;
    const result = addEmailsToCache(emails, esCache);

    const after = esCache.cacheSize - before;
    const inserted = esCache.esCache.size - size_before;
    const size = getAllEmailSize(emails);

    expect(result.success).toBe(true);
    expect(inserted).toBe(number);
    expect(after).toBe(size);
  });

  it('getEmailFromCache retrieves an email by id', async () => {
    const email = emails[0];
    const esCache = await createCacheFromDB(key, db);
    const got = await getEmailFromCache(email.id, esCache);

    expect(got).toStrictEqual(email);
  });

  it('deleteEmailFromCache removes an email and updates size', async () => {
    const esCache = await createCacheFromDB(key, db);
    const size_before = esCache.esCache.size;
    const cache_before = esCache.cacheSize;
    const email = emails[0];
    const emailSize = getEmailSize(email);
    await deleteEmailFromCache(email.id, esCache);
    expect(esCache.esCache.size).toBe(size_before - 1);
    expect(esCache.cacheSize).toBe(cache_before - emailSize);
  });

  it('cacheEmailsFromIDB should work for an empty database', async () => {
    const id = 'non-existant-user';
    const emptyDB = await openDatabase(id);
    const cache = await createCacheFromDB(key, emptyDB);
    const count = await getEmailCount(emptyDB);

    expect(count).toBe(0);
    expect(cache.esCache.size).toBe(0);
    expect(cache.cacheSize).toBe(0);

    closeDatabase(emptyDB);
    deleteDatabase(id);
  });

  it('cacheEmailsFromIDB should work with batches', async () => {
    const id = 'big-db';
    const number = 200;
    const many_emails = generateTestEmails(number);
    const totalSize = getAllEmailSize(many_emails);
    const bigDB = await openDatabase(id);
    await encryptAndStoreManyEmail(many_emails, key, bigDB);
    const cache = await createCacheFromDB(key, bigDB);
    const count = await getEmailCount(bigDB);

    expect(count).toBe(number);
    expect(cache.esCache.size).toBe(number);
    expect(cache.cacheSize).toBe(totalSize);
  });
});
