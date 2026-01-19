export type EncryptedKeystore = {
  userEmail: string;
  type: KeystoreType;
  encryptedKeys: EmailKeysEncrypted;
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

export type PublicKeysBase64 = {
  eccPublicKeyBase64: string;
  kyberPublicKeyBase64: string;
};

export type PrivateKeys = {
  eccPrivateKey: CryptoKey;
  kyberPrivateKey: Uint8Array;
};

export type PrivateKeysEncrypted = {
  eccPrivateKeyBase64: string;
  kyberPrivateKeyBase64: string;
};

export type EmailKeys = {
  publicKeys: PublicKeys;
  privateKeys: PrivateKeys;
};

export type EmailKeysEncrypted = {
  publicKeys: PublicKeysBase64;
  privateKeys: PrivateKeysEncrypted;
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
