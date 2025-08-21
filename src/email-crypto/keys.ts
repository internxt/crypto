import { generateEccKeys } from '../asymmetric-crypto';
import { generateKyberKeys } from '../post-quantum-crypto';
import { PublicKeys, PrivateKeys, User } from '../utils';

/**
 * Generates public and private keys for email service.
 * @returns The user's private and public keys
 */
export async function generateEmailKeys(user: User): Promise<{ publicKeys: PublicKeys; privateKeys: PrivateKeys }> {
  try {
    const kyberKeys = generateKyberKeys();
    const keys = await generateEccKeys();

    const privateKeys: PrivateKeys = {
      eccPrivateKey: keys.privateKey,
      kyberPrivateKey: kyberKeys.secretKey,
    };

    const publicKeys: PublicKeys = {
      user,
      eccPublicKey: keys.publicKey,
      kyberPublicKey: kyberKeys.publicKey,
    };

    return { publicKeys, privateKeys };
  } catch (error) {
    return Promise.reject(new Error('Could not generate keys for email service', error));
  }
}
