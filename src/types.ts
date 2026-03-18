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

export type UserWithPublicKey = User & {
  publicHybridKey: Uint8Array;
};

export type HybridKeyPair = {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
};

export type HybridEncryptedEmail = {
  encryptedKey: HybridEncKey;
  enc: EmailBodyEncrypted;
  recipientEmail: string;
  params: EmailPublicParameters;
  id: string;
  isSubjectEncrypted: boolean;
};

export type PwdProtectedEmail = {
  encryptedKey: PwdProtectedKey;
  enc: EmailBodyEncrypted;
  params: EmailPublicParameters;
  id: string;
  isSubjectEncrypted: boolean;
};

export type StoredEmail = {
  params: EmailPublicParameters;
  enc: EmailBodyEncrypted;
  id: string;
};

export type HybridEncKey = {
  kyberCiphertext: string;
  encryptedKey: string;
};

export type PwdProtectedKey = {
  encryptedKey: string;
  salt: string;
};

export type EmailBodyEncrypted = {
  encText: string;
  encAttachments?: string[];
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
  ENCRYPTION = 'Encryption',
  RECOVERY = 'Recovery',
}
