import { generateEccKeys } from '../asymmetric-crypto';
import { generateKyberKeys } from '../post-quantum-crypto';
import { PublicKeys, PrivateKeys } from '../types';

/**
 * Generates public and private keys for email service.
 *
 * @returns The user's private and public keys
 */
export async function generateEmailKeys(): Promise<{ publicKeys: PublicKeys; privateKeys: PrivateKeys }> {
  try {
    const kyberKeys = generateKyberKeys();
    const keys = await generateEccKeys();

    const privateKeys: PrivateKeys = {
      eccPrivateKey: keys.privateKey,
      kyberPrivateKey: kyberKeys.secretKey,
    };

    const publicKeys: PublicKeys = {
      eccPublicKey: keys.publicKey,
      kyberPublicKey: kyberKeys.publicKey,
    };

    return { publicKeys, privateKeys };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return Promise.reject(new Error(`Failed to generate keys for email service: ${errorMessage}`));
  }
}
