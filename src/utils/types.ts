export enum KeystoreType {
  IDENTITY = 'identity',
  ENCRYPTION = 'encryption',
  RECOVERY = 'recovery',
  INDEX = 'index',
}

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

export type EncryptedEmailHybrid = {
  encryptedEmail: Uint8Array;
  kyberCiphertext: Uint8Array;
  encryptedKey: Uint8Array;
  iv: Uint8Array;
};

export type EncryptedEmailPwd = {
  encryptedEmail: Uint8Array;
  encryptedKey: Uint8Array;
  iv: Uint8Array;
  salt: Uint8Array;
};

export type Email = {
  id: string;
  subject: string;
  body: string;
  sender: string;
  recipient: string[];
  date: string;
  labels?: string[];
};
