import { AxiosResponse } from 'axios';
import { KeystoreType } from '../utils/types';
import { sendKeystore, getKeystoreFromServer } from './api';

export async function sendEncryptionKeystoreToServer(encryptedKeystore: Uint8Array): Promise<AxiosResponse> {
  return sendKeystore(encryptedKeystore, KeystoreType.ENCRYPTION);
}

export async function sendIdentityKeystoreToServer(encryptedKeystore: Uint8Array): Promise<AxiosResponse> {
  return sendKeystore(encryptedKeystore, KeystoreType.IDENTITY);
}

export async function sendRecoveryKeystoreToServer(encryptedKeystore: Uint8Array): Promise<AxiosResponse> {
  return sendKeystore(encryptedKeystore, KeystoreType.RECOVERY);
}

export async function sendIndexKeystoreToServer(encryptedKeystore: Uint8Array): Promise<AxiosResponse> {
  return sendKeystore(encryptedKeystore, KeystoreType.INDEX);
}

export async function getEncryptionKeystoreFromServer(): Promise<Uint8Array> {
  return getKeystoreFromServer(KeystoreType.ENCRYPTION);
}

export async function getIdentityKeystoreFromServer(): Promise<Uint8Array> {
  return getKeystoreFromServer(KeystoreType.IDENTITY);
}

export async function getRecoveryKeystoreFromServer(): Promise<Uint8Array> {
  return getKeystoreFromServer(KeystoreType.RECOVERY);
}

export async function getIndexKeystoreFromServer(): Promise<Uint8Array> {
  return getKeystoreFromServer(KeystoreType.INDEX);
}
