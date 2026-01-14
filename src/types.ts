export type EncryptedKeystore = {
  userEmail: string;
  type: KeystoreType;
  encryptedKeys: Uint8Array;
};

export type User = {
  email: string;
  name: string;
};

export type UserWithPublicKeys = User & {
  publicKeys: PublicKeys;
};

export type PublicKeys = {
  eccPublicKey: CryptoKey;
  kyberPublicKey: Uint8Array;
};

export type PrivateKeys = {
  eccPrivateKey: CryptoKey;
  kyberPrivateKey: Uint8Array;
};

export type EmailKeys = {
  publicKeys: PublicKeys;
  privateKeys: PrivateKeys;
};

export type HybridEncryptedEmail = {
  encryptedKey: HybridEncKey;
  enc: Uint8Array;
  recipientEmail: string;
  params: EmailPublicParameters;
  id: string;
};

export type PwdProtectedEmail = {
  encryptedKey: PwdProtectedKey;
  enc: Uint8Array;
  params: EmailPublicParameters;
  id: string;
};

export type StoredEmail = {
  params: EmailPublicParameters;
  content: Uint8Array;
  id: string;
};

export type HybridEncKey = {
  kyberCiphertext: Uint8Array;
  encryptedKey: Uint8Array;
};

export type PwdProtectedKey = {
  encryptedKey: Uint8Array;
  salt: Uint8Array;
};

export type EmailBody = {
  text: string;
  attachments?: string[];
};

export type EmailPublicParameters = {
  subject: string;
  createdAt: string;
  sender: User;
  recipient: User;
  recipients?: User[];
  replyToEmailID?: string;
  labels?: string[];
};

export type Email = {
  id: string;
  body: EmailBody;
  params: EmailPublicParameters;
};

export interface MailCache<Email> {
  esCache: Map<string, Email>;
  cacheSize: number;
  isCacheLimited: boolean;
  isCacheReady: boolean;
}
export interface EmailSearchResult {
  email: Email;
  score?: number;
}

export enum KeystoreType {
  ENCRYPTION = 'Encryption keystore',
  RECOVERY = 'Recovery keystore',
}
