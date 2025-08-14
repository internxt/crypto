import { ECC_ALGORITHM, AES_KEY_BIT_LENGTH } from '../utils/constants';

export async function deriveEccBits(recipientPublicKey: CryptoKey, userPrivateKey: CryptoKey): Promise<Uint8Array> {
  try {
    const result = await crypto.subtle.deriveBits(
      {
        name: ECC_ALGORITHM,
        public: recipientPublicKey,
      },
      userPrivateKey,
      AES_KEY_BIT_LENGTH,
    );
    return new Uint8Array(result);
  } catch (error) {
    return Promise.reject(new Error(`Failed to derive ECC bits: ${error.message}`));
  }
}
