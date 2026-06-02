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
  encEmail: EmailEncrypted;
};

export type HybridEncryptedEmailAndSubject = {
  encryptedKey: HybridEncKey;
  encEmail: EmailAndSubjectEncrypted;
};

export type PwdProtectedEmail = {
  encryptedKey: PwdProtectedKey;
  encEmail: EmailEncrypted;
};

export type PwdProtectedEmailAndSubject = {
  encryptedKey: PwdProtectedKey;
  encEmail: EmailAndSubjectEncrypted;
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

export type EmailEncrypted = {
  encText: string;
};

export type EmailAndSubjectEncrypted = EmailEncrypted & {
  encSubject: string;
};

export type Email = {
  text: string;
};

export type EmailAndSubject = Email & {
  subject: string;
};

export enum KeystoreType {
  ENCRYPTION = 'Encryption',
  RECOVERY = 'Recovery',
}
