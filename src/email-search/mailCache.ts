import { MAX_CACHE_SIZE, MAX_EMAIL_PER_BATCH } from '../constants';
import { getEmailBatch, getAllEmailsSortedNewestFirst, getEmailCount, MailDB } from './indexedDB';
import { Email } from '../types';
import { emailToBinary } from '../email-crypto';

export interface MailCache<Email> {
  esCache: Map<string, Email>;
  cacheSize: number;
  isCacheLimited: boolean;
  isCacheReady: boolean;
}

function sizeOfEmail(email: Email): number {
  return emailToBinary(email).byteLength;
}

export const cacheEmailBatch = async (emails: Email[], esCache: MailCache<Email>): Promise<boolean> => {
  for (const email of emails) {
    const { success } = addEmailToCache(email, esCache);
    if (!success) return true;
  }

  return false;
};

export const cacheEmailsFromIDB = async (indexKey: CryptoKey, esCache: MailCache<Email>, esDB: MailDB) => {
  esCache.isCacheReady = false;
  try {
    const count = await getEmailCount(esDB);
    if (!count) {
      esCache.isCacheReady = true;
      return;
    }

    if (count <= MAX_EMAIL_PER_BATCH) {
      const emails = await getAllEmailsSortedNewestFirst(esDB, indexKey);
      addEmailsToCache(emails, esCache);
    } else {
      let nextCursor: IDBValidKey | undefined = undefined;

      let cacheFull = false;
      while (!cacheFull) {
        const { emails, nextCursor: newCursor } = await getEmailBatch(esDB, indexKey, MAX_EMAIL_PER_BATCH, nextCursor);
        if (!newCursor || !emails.length) break;
        nextCursor = newCursor;

        const success = addEmailsToCache(emails, esCache);
        if (!success) cacheFull = true;

        // To avoid blocking UI
        await new Promise((resolve) => setTimeout(resolve, 0));
      }
    }
  } catch (error) {
    throw new Error(`Email caching failed: ${error}`);
  } finally {
    esCache.isCacheReady = true;
  }
};

export const getEmailFromCache = async (emailID: string, esCache: MailCache<Email>): Promise<Email> => {
  const email = esCache.esCache.get(emailID);
  if (!email) {
    throw new Error(`Email not found in cache for ID: ${emailID}`);
  }
  return email;
};

export const deleteEmailFromCache = async (emailID: string, esCache: MailCache<Email>) => {
  const email = await getEmailFromCache(emailID, esCache);
  if (!email) return;
  const size = sizeOfEmail(email);
  const removed = esCache.esCache.delete(emailID);
  if (removed) esCache.cacheSize -= size;
};

export function addEmailsToCache(emails: Email[], esCache: MailCache<Email>): { success: boolean; reason?: string } {
  for (const email of emails) {
    const result = addEmailToCache(email, esCache);
    if (!result.success) return result;
  }
  return { success: true };
}

export const addEmailToCache = (email: Email, esCache: MailCache<Email>): { success: boolean; reason?: string } => {
  const emailSize = sizeOfEmail(email);

  if (esCache.cacheSize + emailSize > MAX_CACHE_SIZE) {
    esCache.isCacheLimited = true;
    return { success: false, reason: 'hit cache limit' };
  }

  esCache.esCache.set(email.params.id, email);
  esCache.cacheSize += emailSize;

  return { success: true };
};
