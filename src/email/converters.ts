import { exportPublicKey, importPublicKey } from '../asymmetric';
import { uint8ArrayToBase64, base64ToUint8Array, UTF8ToUint8, uint8ToUTF8, decodeBase64 } from '../utils/converters';
import { EmailBody, PublicKeys, PublicKeysBase64, HybridEncKey, PwdProtectedKey } from '../utils/types';

/**
 * Converts an email body type into a Uint8Array array.
 *
 * @param body - The email body.
 * @returns The Uint8Array array representation of the email body.
 */
export function emailBodyToBinary(body: EmailBody): Uint8Array {
  try {
    const json = JSON.stringify(body);
    const buffer = UTF8ToUint8(json);
    return buffer;
  } catch (error) {
    throw new Error(`Cannot convert email to Uint8Array: ${error}`);
  }
}

/**
 * Converts an Uint8Array array into a email body type.
 *
 * @param body -  The Uint8Array array.
 * @returns The email body.
 */
export function binaryToEmailBody(array: Uint8Array): EmailBody {
  try {
    const json = uint8ToUTF8(array);
    const email: EmailBody = JSON.parse(json);
    return email;
  } catch (error) {
    throw new Error(`Cannot convert Uint8Array to email: ${error}`);
  }
}

export async function base64ToPublicKey(key: PublicKeysBase64): Promise<PublicKeys> {
  try {
    const eccPublicKeyBytes = base64ToUint8Array(key.eccPublicKey);
    const eccPublicKey = await importPublicKey(eccPublicKeyBytes);
    const kyberPublicKey = base64ToUint8Array(key.kyberPublicKey);
    return { eccPublicKey, kyberPublicKey, user: key.user };
  } catch (error) {
    return Promise.reject(new Error(`Cannot convert base64 public key to public key: ${error}`));
  }
}

export async function publicKeyToBase64(key: PublicKeys): Promise<PublicKeysBase64> {
  try {
    const eccPublicKeyArray = await exportPublicKey(key.eccPublicKey);
    const eccPublicKey = uint8ArrayToBase64(eccPublicKeyArray);
    const kyberPublicKey = uint8ArrayToBase64(key.kyberPublicKey);
    return { eccPublicKey, kyberPublicKey, user: key.user };
  } catch (error) {
    return Promise.reject(new Error(`Cannot convert public key to base64 public key: ${error}`));
  }
}

export function encHybridKeyToBase64(encHybridKey: HybridEncKey): string {
  try {
    const json = JSON.stringify({
      kyberCiphertext: uint8ArrayToBase64(encHybridKey.kyberCiphertext),
      encryptedKey: uint8ArrayToBase64(encHybridKey.encryptedKey),
    });
    const base64 = btoa(json);
    return base64;
  } catch (error) {
    throw new Error(`Cannot convert key to base64: ${error}`);
  }
}

export function base64ToEncHybridKey(base64: string): HybridEncKey {
  try {
    const json = decodeBase64(base64);
    const obj = JSON.parse(json);
    return {
      encryptedKey: base64ToUint8Array(obj.encryptedKey),
      kyberCiphertext: base64ToUint8Array(obj.kyberCiphertext),
    };
  } catch (error) {
    throw new Error(`Cannot convert base64 to key: ${error}`);
  }
}

export function pwdProtectedKeyToBase64(pwdProtectedKey: PwdProtectedKey): string {
  try {
    const json = JSON.stringify({
      encryptedKey: uint8ArrayToBase64(pwdProtectedKey.encryptedKey),
      salt: uint8ArrayToBase64(pwdProtectedKey.salt),
    });
    const base64 = btoa(json);
    return base64;
  } catch (error) {
    throw new Error(`Cannot convert key to base64: ${error}`);
  }
}

export function base64ToPwdProtectedKey(base64: string): PwdProtectedKey {
  try {
    const json = decodeBase64(base64);
    const obj = JSON.parse(json);
    return {
      encryptedKey: base64ToUint8Array(obj.encryptedKey),
      salt: base64ToUint8Array(obj.salt),
    };
  } catch (error) {
    throw new Error(`Cannot convert base64 to key: ${error}`);
  }
}
