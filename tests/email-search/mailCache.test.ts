import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import {
  addEmailToCache,
  addEmailsToCache,
  getEmailFromCache,
  deleteEmailFromCache,
  MailCache,
  deleteDatabase,
  openDatabase,
  encryptAndStoreManyEmail,
  closeDatabase,
  cacheEmailsFromIDB,
  getEmailCount,
} from '../../src/email-search';
import { Email } from '../../src/types';
import { genSymmetricCryptoKey } from '../../src/symmetric-crypto';
import { generateTestEmails, generateTestEmail, getAllEmailSize, getEmailSize } from './helper';

describe('Test mail cache functions', () => {
  beforeAll(async () => {
    await deleteDatabase(userID);
    esCache = {
      esCache: new Map(),
      cacheSize: 0,
      isCacheLimited: false,
      isCacheReady: true,
    };
    key = await genSymmetricCryptoKey();
    db = await openDatabase(userID);
    await encryptAndStoreManyEmail(emails, key, db);
  });

  afterAll(async () => {
    closeDatabase(db);
  });

  let esCache: MailCache<Email>;
  const emailNumber = 5;
  const emails: Email[] = generateTestEmails(emailNumber);
  const userID = 'mock ID';
  let db;
  let key;

  it('cacheEmailsFromIDB sucessfully reads emails form database', async () => {
    await cacheEmailsFromIDB(key, esCache, db);
    const totalSize = getAllEmailSize(emails);

    const count = await getEmailCount(db);
    expect(count).toBe(emailNumber);

    expect(esCache.esCache.size).toBe(emailNumber);
    expect(esCache.cacheSize).toBe(totalSize);
    expect(esCache.esCache.get(emails[0].params.id)).toEqual(emails[0]);
  });

  it('addEmailToCache adds an email and updates size', () => {
    const email = generateTestEmail();
    const sizeBefore = esCache.cacheSize;
    const result = addEmailToCache(email, esCache);
    const diff = esCache.cacheSize - sizeBefore;
    const emailSize = getEmailSize(email);

    expect(result.success).toBe(true);
    expect(diff).toBe(emailSize);
    expect(esCache.esCache.size).toBe(emailNumber + 1);
  });

  it('addEmailToCache will not add the same email twice', () => {
    const email = generateTestEmail();

    const result = addEmailToCache(email, esCache);
    expect(result.success).toBe(true);

    const sizeBeforeSecondInsert = esCache.esCache.size;
    expect(sizeBeforeSecondInsert).toBe(emailNumber + 2);

    const result_repeated = addEmailToCache(email, esCache);

    expect(result_repeated.success).toBe(true);
    expect(esCache.esCache.size).toBe(sizeBeforeSecondInsert);
  });

  it('addEmailsToCache adds multiple emails', () => {
    const number = 3;
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
    const got = await getEmailFromCache(email.params.id, esCache);

    expect(got).toStrictEqual(email);
  });

  it('deleteEmailFromCache removes an email and updates size', async () => {
    const size_before = esCache.esCache.size;
    const cache_before = esCache.cacheSize;
    const email = emails[0];
    const emailSize = getEmailSize(email);
    await deleteEmailFromCache(email.params.id, esCache);
    expect(esCache.esCache.size).toBe(size_before - 1);
    expect(esCache.cacheSize).toBe(cache_before - emailSize);
  });
});
