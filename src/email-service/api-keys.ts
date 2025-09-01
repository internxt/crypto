import axios from 'axios';

/**
 * Obtains recipients public keys from the server
 *
 * @param emails - The recipients' emails
 * @returns The list of recipients' public keys
 */
export async function getRecipientsPublicKeysFromServer(emails: string[]): Promise<string[]> {
  try {
    const response = await axios.get<string[]>('/api/getPublicKeys', {
      params: {
        emails: emails,
      },
      withCredentials: true,
      headers: {
        'Content-Type': 'application/json',
      },
    });
    return response.data;
  } catch (error) {
    if (axios.isAxiosError(error)) {
      if (error.response?.status === 401) {
        throw new Error('Unauthorized: Invalid or expired token');
      }
      if (error.response?.status === 403) {
        throw new Error('Forbidden: Insufficient permissions');
      }
      if (error.response?.status === 404) {
        throw new Error('User is not found');
      } else {
        throw new Error('AxiosError:', error);
      }
    }
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to retrieve public keys: ${errorMessage}`);
  }
}
