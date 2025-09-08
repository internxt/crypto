import { describe, it, expect, beforeAll } from 'vitest';
import {
  MailCache,
  openDatabase,
  createSearchIndex,
  searchEmails,
  buildSearchIndexFromCache,
  encryptAndStoreManyEmail,
  cacheEmailsFromIDB,
  deleteDatabase,
} from '../../src/email-search';
import { Email } from '../../src/types';
import { genSymmetricCryptoKey } from '../../src/symmetric-crypto';
import { generateTestEmails } from './helper';

describe('Email Search', () => {
  beforeAll(async () => {
    await deleteDatabase(userID);
    esCache = {
      esCache: new Map(),
      cacheSize: 0,
      isCacheLimited: false,
      isCacheReady: true,
    };
    searchIndex = createSearchIndex();
    key = await genSymmetricCryptoKey();
    db = await openDatabase(userID);
    await encryptAndStoreManyEmail(emails, key, db);
  });
  let esCache: MailCache<Email>;
  const emailNumber = 5;
  const emails: Email[] = generateTestEmails(emailNumber);
  const userID = 'mock ID';
  let db;
  let key;

  let searchIndex = createSearchIndex();

  it('should build search index from cache', async () => {
    await cacheEmailsFromIDB(key, esCache, db);
    await buildSearchIndexFromCache(esCache, searchIndex);

    const result = await searchEmails('Test Subject', esCache, searchIndex);

    expect(result.length).toBe(emailNumber);
  });
});
