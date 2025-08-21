import { ECC_ALGORITHM, AES_KEY_BIT_LENGTH } from '../utils/constants';

/**
 * Derives secret key from the other user's public key and own private key
 * @param otherUserPublicKey - The public key of the other user
 * @param ownPrivateKey - The private key
 * @returns The derived secret key bits
 */
export async function deriveSecretKey(otherUserPublicKey: CryptoKey, ownPrivateKey: CryptoKey): Promise<Uint8Array> {
  try {
    const result = await crypto.subtle.deriveBits(
      {
        name: ECC_ALGORITHM,
        public: otherUserPublicKey,
      },
      ownPrivateKey,
      AES_KEY_BIT_LENGTH,
    );
    return new Uint8Array(result);
  } catch (error) {
    return Promise.reject(new Error(`Failed to derive elliptic curve secret key: ${error.message}`));
  }
}
