import { MAX_CACHE_SIZE, MAX_EMAIL_PER_BATCH } from '../constants';
import { getEmailBatch, getAllEmailsSortedNewestFirst, openDatabase, getEmailCount, MailDB } from './indexedDB';
import { Email } from '../types';
import { emailToBinary } from '../email-crypto';

import React from 'react';

export interface MailCache<Email> {
  esCache: Map<string, Email>;
  cacheSize: number;
  isCacheLimited: boolean;
  isCacheReady: boolean;
}

function sizeOfEmail(email: Email): number {
  return emailToBinary(email).byteLength;
}

export const cacheEmailBatch = async (
  emails: Email[],
  esCacheRef: React.MutableRefObject<MailCache<Email>>,
): Promise<boolean> => {
  for (const email of emails) {
    const { success } = addEmailToCache(email, esCacheRef);
    if (!success) return true;
  }

  return false;
};

export const cacheEmailsFromIDB = async (
  userID: string,
  indexKey: CryptoKey,
  esCacheRef: React.MutableRefObject<MailCache<Email>>,
) => {
  esCacheRef.current.isCacheReady = false;
  let esDB: MailDB | undefined;
  try {
    esDB = await openDatabase(userID);

    const count = await getEmailCount(esDB);
    if (!count) {
      esCacheRef.current.isCacheReady = true;
      return;
    }

    if (count <= MAX_EMAIL_PER_BATCH) {
      const emails = await getAllEmailsSortedNewestFirst(esDB, indexKey);
      addEmailsToCache(emails, esCacheRef);
    } else {
      let nextCursor: IDBValidKey | undefined = undefined;

      let cacheFull = false;
      while (!cacheFull) {
        const { emails, nextCursor: newCursor } = await getEmailBatch(esDB, indexKey, MAX_EMAIL_PER_BATCH, nextCursor);
        if (!newCursor || !emails.length) break;
        nextCursor = newCursor;

        const success = addEmailsToCache(emails, esCacheRef);
        if (!success) cacheFull = true;

        // To avoid blocking UI
        await new Promise((resolve) => setTimeout(resolve, 0));
      }
    }
  } catch (error) {
    throw new Error(`Email caching failed: ${error}`);
  } finally {
    if (esDB) esDB.close();
    esCacheRef.current.isCacheReady = true;
  }
};

export const getEmailFromCache = async (emailID: string, esCacheRef: React.MutableRefObject<MailCache<Email>>) => {
  return esCacheRef.current.esCache.get(emailID);
};

export const deleteEmailFromCache = async (emailID: string, esCacheRef: React.MutableRefObject<MailCache<Email>>) => {
  const email = await getEmailFromCache(emailID, esCacheRef);
  if (!email) return;
  const size = sizeOfEmail(email);
  const removed = esCacheRef.current.esCache.delete(emailID);
  if (removed) esCacheRef.current.cacheSize -= size;
};

export function addEmailsToCache(
  emails: Email[],
  esCacheRef: React.MutableRefObject<MailCache<Email>>,
): { success: boolean; reason?: string } {
  for (const email of emails) {
    const result = addEmailToCache(email, esCacheRef);
    if (!result.success) return result;
  }
  return { success: true };
}

export const addEmailToCache = (
  email: Email,
  esCacheRef: React.MutableRefObject<MailCache<Email>>,
): { success: boolean; reason?: string } => {
  const emailSize = sizeOfEmail(email);

  if (esCacheRef.current.cacheSize + emailSize > MAX_CACHE_SIZE) {
    esCacheRef.current.isCacheLimited = true;
    return { success: false, reason: 'hit cache limit' };
  }

  esCacheRef.current.esCache.set(email.params.id, email);
  esCacheRef.current.cacheSize += emailSize;

  return { success: true };
};
