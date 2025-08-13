import { AxiosResponse } from 'axios';
import { KeystoreType } from '../utils/types';
import { sendKeystore, getKeystore } from './api';

export async function sendEncryptionKeystore(
  encryptedKeystore: Uint8Array,
  userID: string,
  token: string,
): Promise<AxiosResponse> {
  return sendKeystore(encryptedKeystore, userID, token, KeystoreType.ENCRYPTION);
}

export async function sendIdentityKeystore(
  encryptedKeystore: Uint8Array,
  userID: string,
  token: string,
): Promise<AxiosResponse> {
  return sendKeystore(encryptedKeystore, userID, token, KeystoreType.IDENTITY);
}

export async function sendRecoveryKeystore(
  encryptedKeystore: Uint8Array,
  userID: string,
  token: string,
): Promise<AxiosResponse> {
  return sendKeystore(encryptedKeystore, userID, token, KeystoreType.RECOVERY);
}

export async function sendIndexKeystore(
  encryptedKeystore: Uint8Array,
  userID: string,
  token: string,
): Promise<AxiosResponse> {
  return sendKeystore(encryptedKeystore, userID, token, KeystoreType.INDEX);
}

export async function getEncryptionKeystore(userID: string, token: string): Promise<Uint8Array> {
  return getKeystore(userID, token, KeystoreType.ENCRYPTION);
}

export async function getIdentityKeystore(userID: string, token: string): Promise<Uint8Array> {
  return getKeystore(userID, token, KeystoreType.IDENTITY);
}

export async function getRecoveryKeystore(userID: string, token: string): Promise<Uint8Array> {
  return getKeystore(userID, token, KeystoreType.RECOVERY);
}

export async function getIndexKeystore(userID: string, token: string): Promise<Uint8Array> {
  return getKeystore(userID, token, KeystoreType.INDEX);
}
