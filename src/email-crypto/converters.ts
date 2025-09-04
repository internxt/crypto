import { exportPublicKey, importPublicKey } from '../asymmetric-crypto';
import { uint8ArrayToBase64, base64ToUint8Array, UTF8ToUint8, uint8ToUTF8, ciphertextToBase64 } from '../utils';
import {
  EmailBody,
  PublicKeys,
  HybridEncKey,
  PwdProtectedKey,
  User,
  EmailPublicParameters,
  HybridEncryptedEmail,
  PwdProtectedEmail,
  Email,
} from '../types';

/**
 * Converts a User type into a base64 string.
 *
 * @param user - The given user.
 * @returns The base64 representation of the user.
 */
export function userToBase64(user: User): string {
  try {
    const json = JSON.stringify(user);
    return btoa(json);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to convert User to base64: ${errorMessage}`);
  }
}

/**
 * Converts a base64 string into a User type
 *
 * @param base64 - The base64 representation of the user.
 * @returns The User type.
 */
export function base64ToUser(base64: string): User {
  try {
    const json = atob(base64);
    const user: User = JSON.parse(json);
    return user;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to convert base64 to User: ${errorMessage}`);
  }
}

/**
 * Converts an EmailBody type into a Uint8Array array.
 *
 * @param body - The email body.
 * @returns The Uint8Array array representation of the EmailBody type.
 */
export function emailBodyToBinary(body: EmailBody): Uint8Array {
  try {
    const json = JSON.stringify(body);
    return UTF8ToUint8(json);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to convert EmailBody to Uint8Array: ${errorMessage}`);
  }
}

/**
 * Converts an Uint8Array array into EmailBody type.
 *
 * @param array - The Uint8Array array.
 * @returns The EmailBody type representation of the Uint8Array.
 */
export function binaryToEmailBody(array: Uint8Array): EmailBody {
  try {
    const json = uint8ToUTF8(array);
    const email: EmailBody = JSON.parse(json);
    return email;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to convert Uint8Array to EmailBody: ${errorMessage}`);
  }
}

/**
 * Converts a base64 string into PublicKeys type.
 *
 * @param base64 - The base64 representation of the public key.
 * @returns The resulting PublicKeys.
 */
export async function base64ToPublicKey(base64: string): Promise<PublicKeys> {
  try {
    const json = atob(base64);
    const obj = JSON.parse(json);
    const eccPublicKeyBytes = base64ToUint8Array(obj.eccPublicKey);
    const eccPublicKey = await importPublicKey(eccPublicKeyBytes);
    const kyberPublicKey = base64ToUint8Array(obj.kyberPublicKey);
    return {
      eccPublicKey: eccPublicKey,
      kyberPublicKey: kyberPublicKey,
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return Promise.reject(new Error(`Failed to convert base64 to PublicKeys: ${errorMessage}`));
  }
}

/**
 * Converts a PublicKeys type into base64 string.
 *
 * @param key - The PublicKeys key.
 * @returns The resulting base64 string.
 */
export async function publicKeyToBase64(key: PublicKeys): Promise<string> {
  try {
    const eccPublicKeyArray = await exportPublicKey(key.eccPublicKey);
    const json = JSON.stringify({
      eccPublicKey: uint8ArrayToBase64(eccPublicKeyArray),
      kyberPublicKey: uint8ArrayToBase64(key.kyberPublicKey),
    });
    const base64 = btoa(json);
    return base64;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return Promise.reject(new Error(`Failed to convert key of the type PublicKeys to base64: ${errorMessage}`));
  }
}

/**
 * Converts a hybrid key of the type HybridEncKey into base64 string.
 *
 * @param encHybridKey - The HybridEncKey key.
 * @returns The resulting base64 key encoding.
 */
export function encHybridKeyToBase64(encHybridKey: HybridEncKey): string {
  try {
    const json = JSON.stringify({
      kyberCiphertext: uint8ArrayToBase64(encHybridKey.kyberCiphertext),
      encryptedKey: uint8ArrayToBase64(encHybridKey.encryptedKey),
    });
    const base64 = btoa(json);
    return base64;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to convert hybrid key to base64: ${errorMessage}`);
  }
}

/**
 * Converts a base64 string into a hybrid key of the type HybridEncKey.
 *
 * @param base - The base64 encoding of the hybrid key.
 * @returns The resulting HybridEncKey key.
 */
export function base64ToEncHybridKey(base64: string): HybridEncKey {
  try {
    const json = atob(base64);
    const obj = JSON.parse(json);
    return {
      encryptedKey: base64ToUint8Array(obj.encryptedKey),
      kyberCiphertext: base64ToUint8Array(obj.kyberCiphertext),
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to convert base64 to hybrid key: ${errorMessage}`);
  }
}

/**
 * Converts a password-protected key of the type PwdProtectedKey into base64 string.
 *
 * @param pwdProtectedKey - The password-protected key of the type PwdProtectedKey.
 * @returns The resulting base64 key encoding.
 */
export function pwdProtectedKeyToBase64(pwdProtectedKey: PwdProtectedKey): string {
  try {
    const json = JSON.stringify({
      encryptedKey: uint8ArrayToBase64(pwdProtectedKey.encryptedKey),
      salt: uint8ArrayToBase64(pwdProtectedKey.salt),
    });
    const base64 = btoa(json);
    return base64;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to convert password-protected key to base64: ${errorMessage}`);
  }
}

/**
 * Converts a base64 string into a password-protected key of the type PwdProtectedKey.
 *
 * @param base64 - The base64 string.
 * @returns The resulting PwdProtectedKey key.
 */
export function base64ToPwdProtectedKey(base64: string): PwdProtectedKey {
  try {
    const json = atob(base64);
    const obj = JSON.parse(json);
    return {
      encryptedKey: base64ToUint8Array(obj.encryptedKey),
      salt: base64ToUint8Array(obj.salt),
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to convert base64 to password-protected key: ${errorMessage}`);
  }
}

/**
 * Converts an email public parameters of type EmailPublicParameters into base64 string.
 *
 * @param params - The EmailPublicParameters email paramaters.
 * @returns The resulting base64 string encoding.
 */
export function paramsToBase64(params: EmailPublicParameters): string {
  try {
    const json = JSON.stringify({
      ...params,
      sender: userToBase64(params.sender),
      recipient: userToBase64(params.recipient),
      recipients: params.recipients?.map(userToBase64),
    });
    const base64 = btoa(json);
    return base64;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to convert email public parameters to base64: ${errorMessage}`);
  }
}

/**
 * Converts a base64 string into an email paramaters of the type EmailPublicParameters.
 *
 * @param base64 - The base64 string.
 * @returns The resulting EmailPublicParameters email parameters.
 */
export function base64ToParams(base64: string): EmailPublicParameters {
  try {
    const json = atob(base64);
    const obj = JSON.parse(json);
    return {
      ...obj,
      sender: base64ToUser(obj.sender),
      recipient: base64ToUser(obj.recipient),
      recipients: obj.recipients?.map(base64ToUser),
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to convert base64 to email params: ${errorMessage}`);
  }
}

/**
 * Converts an encrypted via hybrid encryption email into base64 string.
 *
 * @param email - The HybridEncryptedEmail encrypted via hybrid encryption email.
 * @returns The resulting base64 string encoding.
 */
export function hybridEncyptedEmailToBase64(email: HybridEncryptedEmail): string {
  try {
    const json = JSON.stringify({
      encryptedKey: encHybridKeyToBase64(email.encryptedKey),
      enc: ciphertextToBase64(email.enc),
      recipientID: email.recipientID,
    });
    const base64 = btoa(json);
    return base64;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to convert hybrid email to base64: ${errorMessage}`);
  }
}

/**
 * Converts a pwd protected email into base64 string.
 *
 * @param email - The PwdProtectedEmail pwd protected email.
 * @returns The resulting base64 string encoding.
 */
export function pwdProtectedEmailToBase64(email: PwdProtectedEmail): string {
  try {
    const json = JSON.stringify({
      encryptedKey: pwdProtectedKeyToBase64(email.encryptedKey),
      enc: ciphertextToBase64(email.enc),
    });
    const base64 = btoa(json);
    return base64;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to convert pwd protected email to base64: ${errorMessage}`);
  }
}

/**
 * Converts an Email type into a Uint8Array array.
 *
 * @param email - The email.
 * @returns The Uint8Array array representation of the Email type.
 */
export function emailToBinary(email: Email): Uint8Array {
  try {
    const json = JSON.stringify(email);
    return UTF8ToUint8(json);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to convert EmailBody to Uint8Array: ${errorMessage}`);
  }
}
