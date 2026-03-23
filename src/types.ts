export type EncryptedKeystore = {
  userEmail: string;
  type: KeystoreType;
  publicKey: string;
  privateKeyEncrypted: string;
};

export type User = {
  email: string;
  name: string;
};

export type RecipientWithPublicKey = {
  email: string;
  publicHybridKey: Uint8Array;
};

export type HybridKeyPair = {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
};

export type HybridEncryptedEmail = {
  encryptedKey: HybridEncKey;
  encEmailBody: EmailBodyEncrypted;
};

export type PwdProtectedEmail = {
  encryptedKey: PwdProtectedKey;
  encEmailBody: EmailBodyEncrypted;
};

export type StoredEmail = {
  params: EmailPublicParameters;
  encEmailBody: EmailBodyEncrypted;
  id: string;
};

export type HybridEncKey = {
  hybridCiphertext: string;
  encryptedKey: string;
  encryptedForEmail: string;
};

export type PwdProtectedKey = {
  encryptedKey: string;
  salt: string;
};

export type EmailBodyEncrypted = {
  encText: string;
  encSubject: string;
  encAttachments?: string[];
};

export type EmailBody = {
  text: string;
  subject: string;
  attachments?: string[];
};

export type EmailPublicParameters = {
  createdAt: string;
  sender: User;
  recipients: User[];
  ccs?: User[];
  bccs?: User[];
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
  ENCRYPTION = 'Encryption',
  RECOVERY = 'Recovery',
}
