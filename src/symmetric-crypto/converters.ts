import { SymmetricCiphertext, uint8ArrayToBase64, decodeBase64, base64ToUint8Array } from '../utils';

export function ciphertextToBase64(cipher: SymmetricCiphertext): string {
  try {
    const ivBase64 = uint8ArrayToBase64(cipher.iv);
    const ciphertextBase64 = uint8ArrayToBase64(cipher.ciphertext);
    const json = JSON.stringify({ ciphertext: ciphertextBase64, iv: ivBase64 });
    const base64 = btoa(json);
    return base64;
  } catch (error) {
    throw new Error(`Cannot convert ciphertext to base64: ${error}`);
  }
}

export function base64ToCiphertext(base64: string): SymmetricCiphertext {
  try {
    const json = decodeBase64(base64);
    const obj = JSON.parse(json);
    const iv = base64ToUint8Array(obj.iv);
    const ciphertext = base64ToUint8Array(obj.ciphertext);
    const result: SymmetricCiphertext = {
      ciphertext,
      iv,
    };
    return result;
  } catch (error) {
    throw new Error(`Cannot convert base64 to ciphertext: ${error}`);
  }
}
