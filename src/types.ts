export enum KeystoreType {
  IDENTITY = 'identity',
  ENCRYPTION = 'encryption',
  RECOVERY = 'recovery',
  INDEX = 'index',
}

export type EncryptedKeystore = {
  userID: string;
  type: KeystoreType;
  encryptedKeys: SymmetricCiphertext;
};

export type User = {
  email: string;
  name: string;
  id: string;
};

export type UserWithPublicKeys = User & {
  publicKeys: PublicKeys;
};

export type PublicKeys = {
  eccPublicKey: CryptoKey;
  kyberPublicKey: Uint8Array;
};

export type MediaKeys = {
  olmKey: Uint8Array;
  pqKey: Uint8Array;
  index: number;
  userID: string;
};

export type PrivateKeys = {
  eccPrivateKey: CryptoKey;
  kyberPrivateKey: Uint8Array;
};

export type IdentityKeys = {
  userPublicKey: CryptoKey;
  userPrivateKey: CryptoKey;
};

export type EncryptionKeys = {
  userPublicKey: CryptoKey;
  userPrivateKey: CryptoKey;
  userPublicKyberKey: Uint8Array;
  userPrivateKyberKey: Uint8Array;
};

export type HybridEncryptedEmail = {
  encryptedKey: HybridEncKey;
  enc: SymmetricCiphertext;
  recipientID: string;
};

export type PwdProtectedEmail = {
  encryptedKey: PwdProtectedKey;
  enc: SymmetricCiphertext;
};

export type SymmetricCiphertext = {
  ciphertext: Uint8Array;
  iv: Uint8Array;
};

export type StoredEmail = {
  params: EmailPublicParameters;
  content: SymmetricCiphertext;
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
  id: string;
  subject: string;
  createdAt: string;
  sender: User;
  recipient: User;
  recipients?: User[];
  replyToEmailID?: number;
  labels?: string[];
};

export type Email = {
  body: EmailBody;
  params: EmailPublicParameters;
};
