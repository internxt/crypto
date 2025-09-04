import { DBSchema, openDB, deleteDB, IDBPDatabase } from 'idb';
import { StoredEmail, Email } from '../types';
import { decryptEmailSymmetrically, encryptEmailContentSymmetricallyWithKey } from '../email-crypto/core';
import { deriveSymmetricCryptoKeyFromContext } from '../derive-key';
import { CONTEXT_INDEX } from '../constants';
import { getAux } from '../email-crypto';

const LABEL = 'email';
const DB_VERSION = 1;
export type MailDB = IDBPDatabase<EncryptedSearchDB>;

export interface EncryptedSearchDB extends DBSchema {
  email: {
    key: string;
    value: StoredEmail;
    indexes: { byTime: number[] };
  };
}

const getDatabaseName = (userID: string): string => {
  return `ES:${userID}:DB`;
};

export const openDatabase = async (userID: string): Promise<MailDB> => {
  const dbName = getDatabaseName(userID);
  return openDB<EncryptedSearchDB>(dbName, DB_VERSION, {
    upgrade(db) {
      if (!db.objectStoreNames.contains(LABEL)) {
        const store = db.createObjectStore(LABEL, { keyPath: 'params.id' });
        store.createIndex('byTime', 'params.date');
      }
    },
  });
};

export const closeDatabase = (esDB: MailDB) => {
  return esDB.close();
};

export const deleteDatabase = async (userID: string) => {
  const dbName = getDatabaseName(userID);
  return deleteDB(dbName);
};

export const deriveIndexKey = async (baseKey: Uint8Array): Promise<CryptoKey> => {
  return deriveSymmetricCryptoKeyFromContext(CONTEXT_INDEX, baseKey);
};

export const encryptAndStoreEmail = async (newEmailToStore: Email, indexKey: CryptoKey, esDB: MailDB) => {
  const aux = getAux(newEmailToStore.params);
  const ciphertext = await encryptEmailContentSymmetricallyWithKey(
    newEmailToStore.body,
    indexKey,
    aux,
    newEmailToStore.params.id,
  );
  const encryptedEmail = { content: ciphertext, params: newEmailToStore.params };
  await esDB.put(LABEL, encryptedEmail);
};

export const encryptAndStoreManyEmail = async (newEmailsToStore: Email[], indexKey: CryptoKey, esDB: MailDB) => {
  const encryptedEmails = await Promise.all(
    newEmailsToStore.map(async (email) => {
      const aux = getAux(email.params);
      const ciphertext = await encryptEmailContentSymmetricallyWithKey(email.body, indexKey, aux, email.params.id);
      return { content: ciphertext, params: email.params };
    }),
  );

  const tr = esDB.transaction(LABEL, 'readwrite');
  await Promise.all([...encryptedEmails.map((encEmail) => tr.store.put(encEmail)), tr.done]);
};

const decryptEmail = async (indexKey: CryptoKey, encryptedEmail: StoredEmail) => {
  const aux = getAux(encryptedEmail.params);
  const email = await decryptEmailSymmetrically(encryptedEmail.content, indexKey, aux);
  return { body: email, params: encryptedEmail.params };
};

export const getAndDecryptEmail = async (ID: string, indexKey: CryptoKey, esDB: MailDB) => {
  const encryptedEmail = await esDB.get(LABEL, ID);
  if (!encryptedEmail) {
    return;
  }
  return decryptEmail(indexKey, encryptedEmail);
};

export const getAndDecryptAllEmails = async (indexKey: CryptoKey, esDB: MailDB) => {
  const encryptedEmails = await esDB.getAll(LABEL);
  const decryptedEmails = await Promise.all(
    encryptedEmails.map(async (encEmail) => {
      const aux = getAux(encEmail.params);
      return await decryptEmailSymmetrically(encEmail.content, indexKey, aux);
    }),
  );

  return decryptedEmails;
};

export const deleteEmail = async (emailID: string, esDB: MailDB): Promise<void> => {
  await esDB.delete(LABEL, emailID);
};

export const getEmailCount = async (esDB: MailDB): Promise<number> => {
  return await esDB.count(LABEL);
};

export const deleteOldestEmails = async (emailsToDelete: number, esDB: MailDB): Promise<void> => {
  const tx = esDB.transaction(LABEL, 'readwrite');
  const index = tx.store.index('byTime');

  let cursor = await index.openCursor();
  let deletedCount = 0;

  while (cursor && deletedCount < emailsToDelete) {
    await cursor.delete();
    deletedCount++;
    cursor = await cursor.continue();
  }

  await tx.done;
};

export const enforceMaxEmailNumber = async (esDB: MailDB, max: number): Promise<void> => {
  const currentCount = await getEmailCount(esDB);
  if (currentCount <= max) {
    return;
  }
  await deleteOldestEmails(currentCount - max, esDB);
};

export const getAllEmailsSortedNewestFirst = async (esDB: MailDB, indexKey: CryptoKey): Promise<Email[]> => {
  const tx = esDB.transaction(LABEL, 'readonly');
  const index = tx.store.index('byTime');

  const encryptedEmails: StoredEmail[] = [];
  let cursor = await index.openCursor(null, 'prev');

  while (cursor) {
    encryptedEmails.push(cursor.value);
    cursor = await cursor.continue();
  }

  const emails = await Promise.all(encryptedEmails.map((encryptedEmail) => decryptEmail(indexKey, encryptedEmail)));

  return emails;
};

export const getAllEmailsSortedOldestFirst = async (esDB: MailDB, indexKey: CryptoKey): Promise<Email[]> => {
  const tx = esDB.transaction(LABEL, 'readonly');
  const index = tx.store.index('byTime');

  const encryptedEmails: StoredEmail[] = [];
  let cursor = await index.openCursor(null, 'next');

  while (cursor) {
    encryptedEmails.push(cursor.value);
    cursor = await cursor.continue();
  }

  const emails = await Promise.all(encryptedEmails.map((encryptedEmail) => decryptEmail(indexKey, encryptedEmail)));

  return emails;
};

export const getEmailBatch = async (
  esDB: MailDB,
  indexKey: CryptoKey,
  batchSize: number,
  startCursor?: IDBValidKey,
): Promise<{ emails: Email[]; nextCursor?: IDBValidKey }> => {
  const tx = esDB.transaction(LABEL, 'readonly');
  const index = tx.store.index('byTime');

  const encryptedEmails: StoredEmail[] = [];
  let cursor;

  if (startCursor) {
    const range = IDBKeyRange.upperBound(startCursor, true);
    cursor = await index.openCursor(range, 'prev');
  } else {
    cursor = await index.openCursor(null, 'prev');
  }

  let count = 0;
  let nextCursor: IDBValidKey | undefined;

  while (cursor && count < batchSize) {
    encryptedEmails.push(cursor.value);
    nextCursor = cursor.key;
    count++;
    cursor = await cursor.continue();
  }

  const emails = await Promise.all(encryptedEmails.map((encryptedEmail) => decryptEmail(indexKey, encryptedEmail)));

  return {
    emails,
    nextCursor: count === batchSize ? nextCursor : undefined,
  };
};
