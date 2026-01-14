import { MAX_CACHE_SIZE, MAX_EMAIL_PER_BATCH } from '../constants';
import { getEmailBatch, getAllEmailsSortedNewestFirst, getEmailCount, MailDB } from './indexedDB';
import { Email, MailCache } from '../types';
import { emailToBinary } from '../email-crypto';

/**
 * Estimates the email size in the memory
 *
 * @param email - The email
 * @returns The estimation of the email size
 */
function sizeOfEmail(email: Email): number {
  return emailToBinary(email).byteLength;
}

/**
 * Creates an empty cache variable
 *
 * @returns The empty cache
 */
function createEmptyCache(): MailCache<Email> {
  return {
    esCache: new Map(),
    cacheSize: 0,
    isCacheLimited: false,
    isCacheReady: true,
  };
}

/**
 * Fetches all emails from the database in batches and cahces them
 *
 * @param indexKey - The symmetric CryptoKey key for protecting database
 * @param esCache - The cache to add emails too
 * @param esDB - The database
 */
export const createCacheFromDB = async (indexKey: CryptoKey, esDB: MailDB): Promise<MailCache<Email>> => {
  const esCache = createEmptyCache();
  esCache.isCacheReady = false;
  try {
    const count = await getEmailCount(esDB);
    if (!count) {
      esCache.isCacheReady = true;
      return esCache;
    }

    if (count <= MAX_EMAIL_PER_BATCH) {
      const emails = await getAllEmailsSortedNewestFirst(esDB, indexKey);
      addEmailsToCache(emails, esCache);
    } else {
      let nextCursor: IDBValidKey | undefined = undefined;

      let cacheFull = false;
      while (!cacheFull) {
        const { emails, nextCursor: newCursor }: { emails: Email[]; nextCursor?: IDBValidKey } = await getEmailBatch(
          esDB,
          indexKey,
          MAX_EMAIL_PER_BATCH,
          nextCursor,
        );
        if (!newCursor || !emails.length) break;
        nextCursor = newCursor;

        const success = addEmailsToCache(emails, esCache);
        if (!success) cacheFull = true;
      }
    }
    return esCache;
  } catch (error) {
    throw new Error(`Email caching failed: ${error}`);
  }
};

/**
 * Gets an email from the cache
 *
 * @param emailID - The email identifier
 * @param esCache - The email cache
 * @returns The found email or throws an error
 */
export const getEmailFromCache = async (emailID: string, esCache: MailCache<Email>): Promise<Email> => {
  const email = esCache.esCache.get(emailID);
  if (!email) {
    throw new Error(`Email not found in cache for ID: ${emailID}`);
  }
  return email;
};

/**
 * Removes the email from cache
 *
 * @param emailID - The email identifier
 * @param esCache - The email cache
 */
export const deleteEmailFromCache = async (emailID: string, esCache: MailCache<Email>): Promise<void> => {
  try {
    const email = await getEmailFromCache(emailID, esCache);
    const size = sizeOfEmail(email);
    const removed = esCache.esCache.delete(emailID);
    if (removed) esCache.cacheSize -= size;
  } catch (error) {
    throw new Error(`Failed to delete email with ID ${emailID}`, { cause: error });
  }
};

/**
 * Adds emails to the cache
 *
 * @param emails - The emails to add
 * @param esCache - The email cache
 * @returns TRUE if all emails were added sucessfully, or FALSE and error reason.
 */
export function addEmailsToCache(emails: Email[], esCache: MailCache<Email>): { success: boolean; reason?: string } {
  try {
    for (const email of emails) {
      const result = addEmailToCache(email, esCache);
      if (!result.success) return result;
    }
    return { success: true };
  } catch (error) {
    throw new Error('Failed to add emails to the cache', { cause: error });
  }
}

/**
 * Adds email to the cache
 *
 * @param email - The email to add
 * @param esCache - The email cache
 * @returns TRUE if the email was added sucessfully, or FALSE and error reason.
 */
export const addEmailToCache = (email: Email, esCache: MailCache<Email>): { success: boolean; reason?: string } => {
  try {
    if (esCache.esCache.has(email.id)) {
      return { success: false, reason: 'email already exists in cache' };
    }

    const emailSize = sizeOfEmail(email);

    if (esCache.cacheSize + emailSize > MAX_CACHE_SIZE) {
      esCache.isCacheLimited = true;
      return { success: false, reason: 'hit cache limit' };
    }

    esCache.esCache.set(email.id, email);
    esCache.cacheSize += emailSize;

    return { success: true };
  } catch (error) {
    throw new Error('Failed to add email to the cache', { cause: error });
  }
};
