export class FailedToEncryptEmail extends Error {
  constructor(errorMsg?: string) {
    super('Failed to encrypt email: ' + errorMsg);

    this.name = this.constructor.name;
    Object.setPrototypeOf(this, FailedToEncryptEmail.prototype);
  }
}

export class EmailSymmetricEncryptionError extends Error {
  constructor(errorMsg?: string) {
    super('Failed to symmetrically encrypt email: ' + errorMsg);

    this.name = this.constructor.name;
    Object.setPrototypeOf(this, EmailSymmetricEncryptionError.prototype);
  }
}

export class EmailSymmetricDecryptionError extends Error {
  constructor(errorMsg?: string) {
    super('Failed to symmetrically decrypt email: ' + errorMsg);

    this.name = this.constructor.name;
    Object.setPrototypeOf(this, EmailSymmetricDecryptionError.prototype);
  }
}

export class EmailPreviewSymmetricDecryptionError extends Error {
  constructor(errorMsg?: string) {
    super('Failed to symmetrically decrypt email preview: ' + errorMsg);

    this.name = this.constructor.name;
    Object.setPrototypeOf(this, EmailPreviewSymmetricDecryptionError.prototype);
  }
}

export class EmailHybridEncryptionError extends Error {
  constructor(errorMsg?: string) {
    super('Failed to hybridly encrypt the key: ' + errorMsg);

    this.name = this.constructor.name;
    Object.setPrototypeOf(this, EmailHybridEncryptionError.prototype);
  }
}

export class EmailHybridDecryptionError extends Error {
  constructor(errorMsg?: string) {
    super('Failed to hybridly decrypt the key: ' + errorMsg);

    this.name = this.constructor.name;
    Object.setPrototypeOf(this, EmailHybridDecryptionError.prototype);
  }
}

export class EmailPasswordProtectError extends Error {
  constructor(errorMsg?: string) {
    super('Failed to password-protect the key: ' + errorMsg);

    this.name = this.constructor.name;
    Object.setPrototypeOf(this, EmailPasswordProtectError.prototype);
  }
}

export class EmailPasswordOpenError extends Error {
  constructor(errorMsg?: string) {
    super('Failed to open password-protected key: ' + errorMsg);

    this.name = this.constructor.name;
    Object.setPrototypeOf(this, EmailPasswordOpenError.prototype);
  }
}

export class InvalidInputEmail extends Error {
  constructor() {
    super('Invalid input');

    this.name = this.constructor.name;
    Object.setPrototypeOf(this, InvalidInputEmail.prototype);
  }
}

export class FailedToDecryptEmail extends Error {
  constructor(errorMsg?: string) {
    super('Failed to decrypt email: ' + errorMsg);

    this.name = this.constructor.name;
    Object.setPrototypeOf(this, FailedToDecryptEmail.prototype);
  }
}
