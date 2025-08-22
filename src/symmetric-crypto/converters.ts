import { SymmetricCiphertext, uint8ArrayToBase64, base64ToUint8Array } from '../utils';

/**
 * Converts encrypted message to base64 string
 *
 * @param encryptedMessage - The encrypted message
 * @returns The resulting base64 string.
 */
export function ciphertextToBase64(encryptedMessage: SymmetricCiphertext): string {
  try {
    const ivBase64 = uint8ArrayToBase64(encryptedMessage.iv);
    const ciphertextBase64 = uint8ArrayToBase64(encryptedMessage.ciphertext);
    const json = JSON.stringify({ ciphertext: ciphertextBase64, iv: ivBase64 });
    const base64 = btoa(json);
    return base64;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to convert ciphertext to base64: ${errorMessage}`);
  }
}

/**
 * Converts base64 string to encrypted message
 *
 * @param base64 - The base64 representation of the encrypted message
 * @returns The resulting encrypted message.
 */
export function base64ToCiphertext(base64: string): SymmetricCiphertext {
  try {
    const json = atob(base64);
    const obj = JSON.parse(json);
    const iv = base64ToUint8Array(obj.iv);
    const ciphertext = base64ToUint8Array(obj.ciphertext);
    const result: SymmetricCiphertext = {
      ciphertext,
      iv,
    };
    return result;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to convert base64 to ciphertext: ${errorMessage}`);
  }
}
