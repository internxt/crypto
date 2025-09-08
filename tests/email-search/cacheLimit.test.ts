import { describe, it, expect, vi } from 'vitest';
import { addEmailToCache } from '../../src/email-search';
import { generateTestEmail } from './helper';

vi.mock('../../src/email-crypto', async () => {
  const actual = await vi.importActual('../../src/email-crypto');
  return {
    ...actual,
    emailToBinary: () => new Uint8Array(700 * 1024 * 1024),
  };
});

describe('Test mail cache limits', () => {
  it('should hit cache limit', () => {
    const esCacheRef = {
      esCache: new Map(),
      cacheSize: 0,
      isCacheLimited: false,
      isCacheReady: true,
    };

    const email = generateTestEmail();
    const result = addEmailToCache(email, esCacheRef);

    expect(result.success).toBe(false);
    expect(result.reason).toBe('hit cache limit');
    expect(esCacheRef.isCacheLimited).toBe(true);
  });
});
