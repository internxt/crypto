export enum KeystoreType {
  IDENTITY = 'identity',
  ENCRYPTION = 'encryption',
  RECOVERY = 'recovery',
  INDEX = 'index',
}

export type User = {
  email: string;
  name: string;
};

export type PublicKeysBase64 = {
  user: User;
  eccPublicKey: string;
  kyberPublicKey: string;
};

export type PublicKeys = {
  user: User;
  eccPublicKey: CryptoKey;
  kyberPublicKey: Uint8Array;
};

export type EncryptedKeystore = {
  iv: Uint8Array;
  encryptedKeys: Uint8Array;
};

export type IdentityKeys = {
  userPublicKey: string;
  userPrivateKey: string;
  serverPublicKey: string;
};

export type EncryptionKeys = {
  userPublicKey: string;
  userPrivateKey: string;
  userPublicKyberKey: string;
  userPrivateKyberKey: string;
};

export type HybridEncryptedEmail = {
  encryptedKey: HybridEncKey;
  ciphertext: symmetricCiphertext;
  sender: User;
  subject: string;
  encryptedFor: User;
  recipients: User[];
  emailChainLength: number;
};

export type PwdProtectedEmail = {
  encryptedKey: PwdProtectedKey;
  ciphertext: symmetricCiphertext;
  sender: User;
  subject: string;
  recipients: User[];
  emailChainLength: number;
};

export type symmetricCiphertext = {
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
  recipients: User[];
  emailChainLength: number;
};
