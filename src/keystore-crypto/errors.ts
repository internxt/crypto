export class FailedToCreateKeyStores extends Error {
  constructor(errorMsg?: string) {
    super('Failed to create encryption and recovery keystores: ' + errorMsg);

    Object.setPrototypeOf(this, FailedToCreateKeyStores.prototype);
  }
}

export class InvalidInputKeyStore extends Error {
  constructor() {
    super('Invalid input');

    Object.setPrototypeOf(this, InvalidInputKeyStore.prototype);
  }
}

export class FailedToOpenEncryptionKeyStore extends Error {
  constructor(errorMsg?: string) {
    super('Failed to open encryption keystore: ' + errorMsg);

    Object.setPrototypeOf(this, FailedToOpenEncryptionKeyStore.prototype);
  }
}

export class FailedToOpenRecoveryKeyStore extends Error {
  constructor(errorMsg?: string) {
    super('Failed to open recovery keystore: ' + errorMsg);

    Object.setPrototypeOf(this, FailedToOpenRecoveryKeyStore.prototype);
  }
}

export class FailedToChangeMnemonicForKeyStore extends Error {
  constructor(errorMsg?: string) {
    super('Error while fetching message: ' + errorMsg);

    Object.setPrototypeOf(this, FailedToChangeMnemonicForKeyStore.prototype);
  }
}
