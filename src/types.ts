export type EncryptedKeystore = {
  userEmail: string;
  type: KeystoreType;
  publicKey: string;
  privateKeyEncrypted: string;
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

export enum KeystoreType {
  ENCRYPTION = 'Encryption',
  RECOVERY = 'Recovery',
}
