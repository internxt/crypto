import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import {
  openDatabase,
  searchEmails,
  buildSearchIndexFromCache,
  encryptAndStoreManyEmail,
  createCacheFromDB,
  deleteDatabase,
  closeDatabase,
} from '../../src/email-search';
import { Email } from '../../src/types';
import { genSymmetricCryptoKey } from '../../src/symmetric-crypto';
import { generateTestEmails, getSearchTestEmails } from './helper';

describe('Email Search', () => {
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
  let db;
  let key;

  it('should build search index from cache', async () => {
    const esCache = await createCacheFromDB(key, db);
    const searchIndex = await buildSearchIndexFromCache(esCache);

    const result = await searchEmails('Test Subject', esCache, searchIndex);

    expect(result.length).toBe(emailNumber);
  });

  it('should search sucessfully', async () => {
    const id = 'test user id';
    const indexKey = await genSymmetricCryptoKey();
    const database = await openDatabase(id);
    const data = [
      'cats abcd efgh ijkl mnop qrst uvwx',
      'cats abcd efgh ijkl mnop qrst ',
      'cats abcd efgh ijkl mnop cute',
      'cats abcd efgh ijkl',
      'cats abcd efgh cute',
      'cats abcd',
      'cats cute',
    ];
    const testEmails = getSearchTestEmails(data);
    await encryptAndStoreManyEmail(testEmails, indexKey, database);
    const cache = await createCacheFromDB(indexKey, database);
    const search = await buildSearchIndexFromCache(cache);

    const result = await searchEmails('cats cute', cache, search);

    expect(result.length).toBe(3);

    const resultInSubjectsOnly = await searchEmails('cats cute', cache, search, {
      fields: ['subject'],
      limit: 5,
    });
    expect(resultInSubjectsOnly.length).toBe(0);

    closeDatabase(database);
  });
});
