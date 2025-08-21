import { encryptSymmetrically, decryptSymmetrically } from '../symmetric-crypto';
import { INDEX_KEYSTORE_TAG, NONCE_LENGTH, SymmetricCiphertext } from '../utils';

const MAX_INDEX_VALUE = Math.pow(2, NONCE_LENGTH * 8);

export async function encryptCurrentSearchIndices(
  secretKey: CryptoKey,
  indices: Uint8Array,
  repeats: number,
  current_aux: string,
): Promise<{
  nonce: number;
  aux: string;
  encIndices: SymmetricCiphertext;
}> {
  let aux = current_aux;
  let nonce = repeats;
  if (repeats >= MAX_INDEX_VALUE) {
    nonce = 0;
    aux = INDEX_KEYSTORE_TAG + new Date().toDateString();
  }
  const result = await encryptSymmetrically(secretKey, repeats, indices, aux);
  return { nonce, aux, encIndices: result };
}

export async function decryptCurrentSearchIndices(
  secretKey: CryptoKey,
  encryptedIndices: SymmetricCiphertext,
  aux: string,
): Promise<Uint8Array> {
  return decryptSymmetrically(secretKey, encryptedIndices, aux);
}
