# Mail cryptographic library

[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=internxt_crypto&metric=ncloc)](https://sonarcloud.io/summary/new_code?id=internxt_crypto)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=internxt_crypto&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=internxt_crypto)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=internxt_crypto&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=internxt_crypto)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=internxt_crypto&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=internxt_crypto)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=internxt_crypto&metric=code_smells)](https://sonarcloud.io/summary/new_code?id=internxt_crypto)
[![Duplicated Lines (%)](https://sonarcloud.io/api/project_badges/measure?project=internxt_crypto&metric=duplicated_lines_density)](https://sonarcloud.io/summary/new_code?id=internxt_crypto)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=internxt_crypto&metric=coverage)](https://sonarcloud.io/summary/new_code?id=internxt_crypto)

# Project Manteinance

We aim to have:

- An 'A' score on Maintainability Rating
- An 'A' score on Security Rating
- Less than 3% duplicated lines
- A 90% tests coverage

## Scripts

### `yarn run lint` (`yarn run lint:ts`)

- Runs .ts linter

### `yarn test` (`vitest run`)

- Runs unit tests with [Vitest](https://vitest.dev/)


### `yarn build`

Builds the app for production to the `build` folder.

## Project Structure

### Core Cryptography Modules

- **`asymmetric-crypto`** - Asymmetric elliptic curves cryptography (curve P-521) for generating keys and deriving a shared secret between two users
- **`symmetric-crypto`** - Symmetric encryption operations (AES-GCM) for data encryption and decryption
- **`post-quantum-crypto`** - Post-quantum cryptographic algorithms (MLKEMs) for generating keys and deriving a shared secret between two users
- **`hash`** - Cryptographic hashing functions (BLAKE3) for data integrity, commitments and secret extensions

### Key Management

- **`derive-key`** - Key derivation functions for deriving cryptographic keys from passwords (ARGON2) and base key (BLAKE3 in KDF mode)
- **`key-wrapper`** - Key wrapping and unwrapping functions for secure symmetric key storage and transport
- **`keystore-crypto`** - Keystore cryptographic operations for securing user's keys
- **`keystore-service`** - Keystore management service for communicating with the server

### Email Security

- **`email-crypto`** - End-to-end email encryption and decryption using hybrid cryptography and password-protection
- **`email-search`** - Email indexing on the client side to enable search while preserving privacy
- **`email-service`** - Email management service for communicating with the server

### Infrastructure

- **`storage-service`** - Abstraction layer for accessing Local Storage and Session Storage
- **`utils`** - Type converter functions and access to enviromental variables
- **`types`** - TypeScript type definitions for all library interfaces and data structures
- **`constants`** - Cryptographic constants, algorithm identifiers, and configuration values

## Usage Example

```typescript
import {
  asymmetric,
  symmetric,
  utils,
  emailCrypto,
  pq,
  keystoreService,
  deriveKey,
  hash,
  SymmetricCiphertext
} from 'internxt-crypto';

// Asymmetric encryption
const keysAlice = await asymmetric.generateEccKeys();
const keysBob = await asymmetric.generateEccKeys();
const resultAlice = await asymmetric.deriveSecretKey(keysBob.publicKey, keysAlice.privateKey);
const resultBob = await asymmetric.deriveSecretKey(keysAlice.publicKey, keysBob.privateKey);
expect(resultAlice).toStrictEqual(resultBob);

// Symmetric encryption
const data = utils.UTF8ToUint8('Sensitive information to encrypt'); // convert to Uint8Array 
const additionalData = 'Additional non-secret data';
const key = await symmetric.genSymmetricCryptoKey(); // CryptoKey 
const ciphertext: SymmetricCiphertext = await symmetric.encryptSymmetrically(key, data, additionalData);
const plainText = await symmetric.decryptSymmetrically(encryptionKey, ciphertext, additionalData);
expect(data).toStrictEqual(plainText);

// Post qunatum cryptography
const keys = pq.generateKyberKeys();
const { cipherText, sharedSecret } = pq.encapsulateKyber(keys.publicKey);
const result = pq.decapsulateKyber(cipherText, keys.secretKey);
expect(result).toStrictEqual(sharedSecret);

// Hash
const result = await hash.hashData(['']);
const expectedResult = 'af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262';
expect(result).toStrictEqual(expectedResult);

// Key derivation
const context = 'BLAKE3 2019-12-27 16:29:52 test vectors context';
const baseKey = symmetric.genSymmetricKey();  // Uint8Array 
const key = await deriveKey.deriveSymmetricCryptoKeyFromContext(context, baseKey);
expect(key).instanceOf(CryptoKey);

const password = 'your password';
const { keyHex, saltHex } = await deriveKey.getKeyFromPasswordHex(password);
const result = await deriveKey.verifyKeyFromPasswordHex(password, saltHex, keyHex);
expect(result).toBe(true);

// Hybrid email encryption

const emailBody: EmailBody = {
    text: 'email text',
    createdAt: '2025-06-14T08:11:22.000Z',
    labels: ['label 1', 'label2'],
};

const userAlice = {
    email: 'alice email',
    name: 'alice',
    id: '1',
};

const userBob = {
    email: 'bob email',
    name: 'bob',
    id: '2',
};
const { privateKeys: alicePrivateKeys, publicKeys: alicePublicKeys } = await emailCrypto.generateEmailKeys();
const { privateKeys: bobPrivateKeys, publicKeys: bobPublicKeys } = await emailCrypto.generateEmailKeys();

const emailBody: EmailBody = {
  text: 'email body',
};

const emailParams: EmailPublicParameters = {
  labels: ['label 1', 'label2'],
  createdAt: '2025-06-14T08:11:22.000Z',
  subject: 'email subject',
  sender: userAlice,
  recipient: userBob,
  replyToEmailID: 2,
};

const email: Email = {
  id: 'email id',
  params: emailParams,
  body: emailBody,
};
const encryptedEmail = await emailCrypto.encryptEmailHybrid(email, bobPublicKeys, alicePrivateKeys);
const decryptedEmail = await emailCrypto.decryptEmailHybrid(encryptedEmail, alicePublicKeys, bobPrivateKeys);
expect(decryptedEmail).toStrictEqual(email);


// password-protected email
const sharedSecret = 'secret shared between Alice and Bob';
const encryptedEmail = await emailCrypto.createPwdProtectedEmail(email, sharedSecret);
const decryptedEmail = await emailCrypto.decryptPwdProtectedEmail(encryptedEmail, sharedSecret);
expect(decryptedEmail).toStrictEqual(email);

// keystore

// For this to work, session storage must have UserID and baseKey
const { encryptionKeystore, recoveryKeystore, recoveryCodes } = await createEncryptionAndRecoveryKeystores();
const result_enc = await keystoreService.openEncryptionKeystore(encryptionKeystore);
const result_rec = await keystoreService.openRecoveryKeystore(recoveryCodes, recoveryKeystore); 
expect(result_enc).toStrictEqual(result_rec);

// Email storage and search

// Between sessions emails are stored encrypted in IndexedDB. The encryption key is derived from user's baseKey
// During the session, all emails are decrypted and stored in the cache (up to 600 MB, if excides - we delete oldests emails)
// For search, we build a search index from cache, then use Flexsearch for the search. 
// The search is doen separately for email content, subject, sender and recivers. 

// Open IndexedDB database
const userID = 'user ID';
const db = await openDatabase(userID);

// Derive database key
const key = await deriveIndexKey(baseKey);

// Encrypt and store one or several emails
await encryptAndStoreEmail(email, key, db);
await encryptAndStoreManyEmail(emails, key, db);

// Delete given email by its ID
await deleteEmail(emailID, db);

// Delete oldests emails
const number = 5;
await deleteOldestEmails(number, db);

// Get all emails with or without sorting
const allEmails = await getAndDecryptAllEmails(key, db);
const newestFirst = await getAllEmailsSortedNewestFirst(db, key);
const oldestFirst = await getAllEmailsSortedOldestFirst(db, key);

// Get the number of stored emails
const count = await getEmailCount(db);

// Close IndexedDB database
closeDatabase(db);

// Delete IndexedDB database
await deleteDatabase(userID);

// Create email cache 
const esCache = await createCacheFromDB(key, db);

// Add one or multiple emails to cache
const result = addEmailToCache(email, esCache);
expect(result.success).toBe(true);

const result = addEmailsToCache(emails, esCache);
expect(result.success).toBe(true);

// Get email from cache by its ID
const email = await getEmailFromCache(emailID, esCache);

// Delete email from cache by its ID
await deleteEmailFromCache(emailID, esCache);

// Create search index and search by query
 const searchIndex = await buildSearchIndexFromCache(esCache);
 const query = 'keywords to search';
 const options = {
    fields: ['subject'], // in which fields to search, all by deafult (subject, body, from, to)
    limit: 5,  // result limit, 50 by default
    boost: { subject: 3, body: 1, from: 2, to: 2 }, // custom waights for matches in different email parts
  };
 const result: EmailSearchResult = await searchEmails(query, esCache, searchIndex);

```