import { DBSchema, openDB, deleteDB, IDBPDatabase } from 'idb';
import { StoredEmail, Email } from '../types';
import { decryptEmailSymmetrically, encryptEmailContentSymmetricallyWithKey } from '../email-crypto/core';
import { deriveSymmetricCryptoKeyFromContext } from '../derive-key';
import { CONTEXT_INDEX, DB_LABEL, DB_VERSION } from '../constants';
import { getAux } from '../email-crypto';

export type MailDB = IDBPDatabase<EncryptedSearchDB>;

export interface EncryptedSearchDB extends DBSchema {
  email: {
    key: string;
    value: StoredEmail;
    indexes: { byTime: number[] };
  };
}

/**
 * Returns IndexedDB database name for the given user
 *
 * @param userID - The user ID
 * @returns The database name
 */
const getDatabaseName = (userID: string): string => {
  return `ES:${userID}:DB`;
};

/**
 * Opens IndexedDB database for the given user
 *
 * @param userID - The user ID
 * @returns The database
 */
export const openDatabase = async (userID: string): Promise<MailDB> => {
  try {
    const dbName = getDatabaseName(userID);
    return openDB<EncryptedSearchDB>(dbName, DB_VERSION, {
      upgrade(db) {
        if (!db.objectStoreNames.contains(DB_LABEL)) {
          const store = db.createObjectStore(DB_LABEL, { keyPath: 'id' });
          store.createIndex('byTime', 'params.createdAt');
        }
      },
    });
  } catch (error) {
    throw new Error(`Cannot open a database for the user ${userID}`, { cause: error });
  }
};

/**
 * Closes the IndexedDB database
 *
 * @param esDB - The database
 */
export const closeDatabase = (esDB: MailDB): void => {
  return esDB.close();
};

/**
 * Deletes IndexedDB database for the given user
 *
 * @param userID - The user ID
 * @returns The database
 */
export const deleteDatabase = async (userID: string): Promise<void> => {
  const dbName = getDatabaseName(userID);
  return deleteDB(dbName);
};

/**
 * Derives database encryption key for the given user
 *
 * @param userID - The user ID
 * @returns The symmetric CryptoKey for protecting database
 */
export const deriveIndexKey = async (baseKey: Uint8Array): Promise<CryptoKey> => {
  return deriveSymmetricCryptoKeyFromContext(CONTEXT_INDEX, baseKey);
};

/**
 * Encrypts the given email and stores it in the IndexedDB database
 *
 * @param newEmailToStore - The email for storing
 * @param indexKey - The symmetric CryptoKey key for protecting database
 * @param esDB - The database
 */
export const encryptAndStoreEmail = async (
  newEmailToStore: Email,
  indexKey: CryptoKey,
  esDB: MailDB,
): Promise<void> => {
  try {
    const aux = getAux(newEmailToStore.params);
    const enc = await encryptEmailContentSymmetricallyWithKey(newEmailToStore.body, indexKey, aux, newEmailToStore.id);
    const encryptedEmail: StoredEmail = { enc, params: newEmailToStore.params, id: newEmailToStore.id };
    await esDB.put(DB_LABEL, encryptedEmail);
  } catch (error) {
    throw new Error('Cannot encrypt and add the given email to the database', { cause: error });
  }
};

/**
 * Encrypts the given set of emails and stores it in the IndexedDB database
 *
 * @param newEmailsToStore - The set of emails for storing
 * @param indexKey - The symmetric CryptoKey key for protecting database
 * @param esDB - The database
 */
export const encryptAndStoreManyEmail = async (
  newEmailsToStore: Email[],
  indexKey: CryptoKey,
  esDB: MailDB,
): Promise<void> => {
  try {
    const encryptedEmails = await Promise.all(
      newEmailsToStore.map(async (email: Email) => {
        const aux = getAux(email.params);
        const enc = await encryptEmailContentSymmetricallyWithKey(email.body, indexKey, aux, email.id);

        return { enc, params: email.params, id: email.id };
      }),
    );

    const tr = esDB.transaction(DB_LABEL, 'readwrite');
    await Promise.all([...encryptedEmails.map((encEmail) => tr.store.put(encEmail)), tr.done]);
  } catch (error) {
    throw new Error('Cannot encrypt and add emails to the database', { cause: error });
  }
};

/**
 * Decrypts the given email
 *
 * @param indexKey - The symmetric CryptoKey key for protecting database
 * @param encryptedEmail - The encrypted email
 * @returns The decrypted email
 */
const decryptEmail = async (indexKey: CryptoKey, encryptedEmail: StoredEmail): Promise<Email> => {
  try {
    const aux = getAux(encryptedEmail.params);
    const email = await decryptEmailSymmetrically(indexKey, aux, encryptedEmail.enc);
    return { body: email, params: encryptedEmail.params, id: encryptedEmail.id };
  } catch (error) {
    throw new Error('Cannot decrypt the given email', { cause: error });
  }
};

/**
 * Fetches the email from the database and decrypts it
 *
 * @param emailID - The email identifier
 * @param indexKey - The symmetric CryptoKey key for protecting database
 * @param encryptedEmail - The encrypted email
 * @returns The decrypted email
 */
export const getAndDecryptEmail = async (emailID: string, indexKey: CryptoKey, esDB: MailDB): Promise<Email> => {
  try {
    const encryptedEmail = await esDB.get(DB_LABEL, emailID);
    if (!encryptedEmail) {
      throw new Error(`DB cannot find email with id ${emailID}`);
    }
    return decryptEmail(indexKey, encryptedEmail);
  } catch (error) {
    throw new Error(`Cannot fetch the email ${emailID} from the database`, { cause: error });
  }
};

/**
 * Fetches all email from the database and decrypts them
 *
 * @param indexKey - The symmetric CryptoKey key for protecting database
 * @param esDB - The database
 * @returns The decrypted emails
 */
export const getAndDecryptAllEmails = async (indexKey: CryptoKey, esDB: MailDB): Promise<Email[]> => {
  try {
    const encryptedEmails = await esDB.getAll(DB_LABEL);

    const decryptedEmails = await Promise.all(
      encryptedEmails.map(async (encEmail) => {
        const aux = getAux(encEmail.params);
        const body = await decryptEmailSymmetrically(indexKey, aux, encEmail.enc);
        return { body, params: encEmail.params, id: encEmail.id };
      }),
    );

    return decryptedEmails.filter((email): email is Email => email !== null);
  } catch (error) {
    throw new Error('Cannot fetch and decrypt all emails from the database', { cause: error });
  }
};

/**
 * Deletes the email from the database
 *
 * @param emailID - The email identifier
 * @param esDB - The database
 */
export const deleteEmail = async (emailID: string, esDB: MailDB): Promise<void> => {
  await esDB.delete(DB_LABEL, emailID);
};

/**
 * Returns the number of stored email
 *
 * @param esDB - The database
 * @returns The number of stored emails
 */
export const getEmailCount = async (esDB: MailDB): Promise<number> => {
  return await esDB.count(DB_LABEL);
};

/**
 * Removes the given number of oldests emails from the database
 *
 * @param emailsToDelete - The number of emails to delete
 * @param esDB - The database
 */
export const deleteOldestEmails = async (emailsToDelete: number, esDB: MailDB): Promise<void> => {
  try {
    const tx = esDB.transaction(DB_LABEL, 'readwrite');
    const index = tx.store.index('byTime');

    let cursor = await index.openCursor();
    let deletedCount = 0;

    while (cursor && deletedCount < emailsToDelete) {
      await cursor.delete();
      deletedCount++;
      cursor = await cursor.continue();
    }

    await tx.done;
  } catch (error) {
    throw new Error(`Cannot delete ${emailsToDelete} oldests emails from the database`, { cause: error });
  }
};

/**
 * Enforces the maximum email number in the database
 *
 * @param esDB - The database
 * @param max - The maximum allowed number of emails
 */
export const enforceMaxEmailNumber = async (esDB: MailDB, max: number): Promise<void> => {
  try {
    const currentCount = await getEmailCount(esDB);
    if (currentCount <= max) {
      return;
    }
    await deleteOldestEmails(currentCount - max, esDB);
  } catch (error) {
    throw new Error(`Cannot enforce the maximum of ${max} emails on the database`, { cause: error });
  }
};

/**
 * Fetches all emails from the database, decrypts them and sortes the results in the specified order
 *
 * @param esDB - The database
 * @param indexKey - The symmetric CryptoKey key for protecting database
 * @param direction - The order of sorting. If 'next' - oldest first, if 'prev' - newest first
 * @returns Decryped emails in the specified order
 */
const fetchEmails = async (esDB: MailDB, indexKey: CryptoKey, direction: 'next' | 'prev'): Promise<Email[]> => {
  try {
    const tx = esDB.transaction(DB_LABEL, 'readonly');
    const index = tx.store.index('byTime');

    const encryptedEmails: StoredEmail[] = [];
    let cursor = await index.openCursor(null, direction);

    while (cursor) {
      encryptedEmails.push(cursor.value);
      cursor = await cursor.continue();
    }

    const emails = await Promise.all(encryptedEmails.map((encryptedEmail) => decryptEmail(indexKey, encryptedEmail)));

    return emails;
  } catch (error) {
    throw new Error('Cannot fetch emails from database', { cause: error });
  }
};

/**
 * Fetches all emails from the database, decrypts them and sortes the results based on the creation time (newest first)
 *
 * @param esDB - The database
 * @param indexKey - The symmetric CryptoKey key for protecting database
 * @returns The number of stored emails
 */
export const getAllEmailsSortedNewestFirst = async (esDB: MailDB, indexKey: CryptoKey): Promise<Email[]> => {
  return fetchEmails(esDB, indexKey, 'prev');
};

/**
 * Fetches all emails from the database, decrypts them and sortes the results based on the creation time (oldest first)
 *
 * @param esDB - The database
 * @param indexKey - The symmetric CryptoKey key for protecting database
 * @returns The number of stored emails
 */
export const getAllEmailsSortedOldestFirst = async (esDB: MailDB, indexKey: CryptoKey): Promise<Email[]> => {
  return fetchEmails(esDB, indexKey, 'next');
};

/**
 * Fetches a batch of emails from the database, decrypts them and sortes the results based on the creation time (newest first)
 *
 * @param esDB - The database
 * @param indexKey - The symmetric CryptoKey key for protecting database
 * @param batchSize - The size of the batch
 * @param startCursor - The starting point (optional). If not given, starts from the beginning
 * @returns The number of stored emails
 */
export const getEmailBatch = async (
  esDB: MailDB,
  indexKey: CryptoKey,
  batchSize: number,
  startCursor?: IDBValidKey,
): Promise<{ emails: Email[]; nextCursor?: IDBValidKey }> => {
  try {
    const tx = esDB.transaction(DB_LABEL, 'readonly');
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
  } catch (error) {
    throw new Error(`Cannot fetch email batch of ${batchSize} from the database`, { cause: error });
  }
};
