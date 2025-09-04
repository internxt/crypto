import { describe, it, expect, vi, beforeEach } from 'vitest';
import axios from 'axios';
import { publicKeyToBase64 } from '../../src/email-crypto';
import { PublicKeys } from '../../src/types';
import { generateEccKeys } from '../../src/asymmetric-crypto';
import { generateKyberKeys } from '../../src/post-quantum-crypto';
import { getRecipientsPublicKeys } from '../../src/email-service';

vi.mock('axios');

describe('Test key service functions', async () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const mockEmail = 'user-email';
  const eccKeyPair = await generateEccKeys();
  const kyberKeyPair = generateKyberKeys();

  const pk: PublicKeys = {
    eccPublicKey: eccKeyPair.publicKey,
    kyberPublicKey: kyberKeyPair.publicKey,
  };

  const pkBase64 = await publicKeyToBase64(pk);

  it('should successfully return recipient public keys with valid parameters', async () => {
    const mockResponse = {
      data: [pkBase64],
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    };

    vi.mocked(axios.get).mockResolvedValue(mockResponse);

    const result = await getRecipientsPublicKeys([mockEmail]);

    expect(axios.get).toHaveBeenCalledWith('/api/getPublicKeys', {
      params: {
        emails: [mockEmail],
      },
      withCredentials: true,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    expect(result).toStrictEqual([pk]);
  });

  it('should handle 401 unauthorized error', async () => {
    const unauthorizedError = {
      isAxiosError: true,
      response: {
        status: 401,
        data: { message: 'Unauthorized' },
      },
    };

    vi.mocked(axios.get).mockRejectedValueOnce(unauthorizedError);
    vi.mocked(axios.isAxiosError).mockReturnValueOnce(true);

    await expect(getRecipientsPublicKeys([mockEmail])).rejects.toThrow('Failed to get recipients public keys');
  });

  it('should handle 403 forbidden error', async () => {
    const forbiddenError = {
      isAxiosError: true,
      response: {
        status: 403,
        data: { message: 'Forbidden' },
      },
    };

    vi.mocked(axios.get).mockRejectedValueOnce(forbiddenError);
    vi.mocked(axios.isAxiosError).mockReturnValueOnce(true);

    await expect(getRecipientsPublicKeys([mockEmail])).rejects.toThrow('Failed to get recipients public keys');
  });

  it('should handle 404 not found error', async () => {
    const notFoundError = {
      isAxiosError: true,
      response: {
        status: 404,
        data: { message: 'Not Found' },
      },
    };

    vi.mocked(axios.get).mockRejectedValueOnce(notFoundError);
    vi.mocked(axios.isAxiosError).mockReturnValueOnce(true);

    await expect(getRecipientsPublicKeys([mockEmail])).rejects.toThrow('Failed to get recipients public keys');
  });

  it('should handle network errors', async () => {
    const networkError = new Error('Network Error');
    vi.mocked(axios.get).mockRejectedValueOnce(networkError);

    await expect(getRecipientsPublicKeys([mockEmail])).rejects.toThrow('Failed to get recipients public keys');
  });

  it('should handle axios errors with an empty response', async () => {
    const errorWithoutResponce = {
      isAxiosError: true,
    };

    vi.mocked(axios.get).mockRejectedValueOnce(errorWithoutResponce);
    vi.mocked(axios.isAxiosError).mockReturnValueOnce(true);

    await expect(getRecipientsPublicKeys([mockEmail])).rejects.toThrow('Failed to get recipients public keys');
  });

  it('should handle non-Error thrown values', async () => {
    vi.mocked(axios.get).mockRejectedValueOnce('Something went wrong');
    await expect(getRecipientsPublicKeys([mockEmail])).rejects.toThrowError(/Failed to get recipients public keys/);
  });
});
