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

export type SearchIndices = {
  userID: string;
  data: Uint8Array;
  timestamp: Date;
};

export type User = {
  email: string;
  name: string;
  id: string;
};

export type PublicKeys = {
  userID: string;
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
  ciphertext: SymmetricCiphertext;
  sender: User;
  subject: string;
  encryptedFor: string;
  recipients: Map<string, User>;
  replyToEmailID?: number;
};

export type PwdProtectedEmail = {
  encryptedKey: PwdProtectedKey;
  ciphertext: SymmetricCiphertext;
  sender: User;
  subject: string;
  recipients: Map<string, User>;
  replyToEmailID?: number;
};

export type SymmetricCiphertext = {
  ciphertext: Uint8Array;
  iv: Uint8Array;
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
  date: string;
  labels?: string[];
  attachments?: string[];
};
export type Email = {
  id: string;
  body: EmailBody;
  subject: string;
  sender: User;
  recipients: Map<string, User>;
  replyToEmailID?: number;
};
