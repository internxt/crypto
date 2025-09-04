import { DBSchema, openDB, deleteDB, IDBPDatabase } from 'idb';
import { StoredEmail, Email } from '../types';
import { decryptEmailSymmetrically, encryptEmailContentSymmetricallyWithKey } from '../email-crypto/core';
import { deriveSymmetricCryptoKeyFromContext } from '../derive-key';
import { CONTEXT_INDEX } from '../constants';
import { getAux } from '../email-crypto';

const LABEL = 'email';
const DB_VERSION = 1;
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

export const openDatabase = async (userID: string): Promise<IDBPDatabase<EncryptedSearchDB>> => {
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

export const closeDatabase = (esDB: IDBPDatabase<EncryptedSearchDB>) => {
  return esDB.close();
};

export const deleteDatabase = async (userID: string) => {
  const dbName = getDatabaseName(userID);
  return deleteDB(dbName);
};

export const deriveIndexKey = async (baseKey: Uint8Array): Promise<CryptoKey> => {
  return deriveSymmetricCryptoKeyFromContext(CONTEXT_INDEX, baseKey);
};

export const encryptAndStoreEmail = async (
  newEmailToStore: Email,
  indexKey: CryptoKey,
  esDB: IDBPDatabase<EncryptedSearchDB>,
) => {
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

export const encryptAndStoreManyEmail = async (
  newEmailsToStore: Email[],
  indexKey: CryptoKey,
  esDB: IDBPDatabase<EncryptedSearchDB>,
) => {
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

export const getAndDecryptEmail = async (ID: string, indexKey: CryptoKey, esDB: IDBPDatabase<EncryptedSearchDB>) => {
  const encryptedEmail = await esDB.get(LABEL, ID);
  if (!encryptedEmail) {
    return;
  }
  const aux = getAux(encryptedEmail.params);
  const email = await decryptEmailSymmetrically(encryptedEmail.content, indexKey, aux);
  return email;
};

export const getAndDecryptAllEmails = async (indexKey: CryptoKey, esDB: IDBPDatabase<EncryptedSearchDB>) => {
  const encryptedEmails = await esDB.getAll(LABEL);
  const decryptedEmails = await Promise.all(
    encryptedEmails.map(async (encEmail) => {
      const aux = getAux(encEmail.params);
      return await decryptEmailSymmetrically(encEmail.content, indexKey, aux);
    }),
  );

  return decryptedEmails;
};

export const deleteEmail = async (emailID: string, esDB: IDBPDatabase<EncryptedSearchDB>): Promise<void> => {
  await esDB.delete(LABEL, emailID);
};

export const getEmailCount = async (esDB: IDBPDatabase<EncryptedSearchDB>): Promise<number> => {
  return await esDB.count(LABEL);
};
