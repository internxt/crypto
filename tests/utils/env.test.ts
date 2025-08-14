import { describe, it, expect } from 'vitest';
import envService from '../../src/utils/env';

describe('Check that env variables are loaded correctly', () => {
  it('When an env variable are requested, then their value is successfully returned', async () => {
    expect(envService.getVariable('serviceID')).toBe('test-service-id');
    expect(envService.getVariable('templateID')).toBe('test-template-id');
    expect(envService.getVariable('publicKey')).toBe('test-public-key');
  });

  it('should throw error for unknown variable', () => {
    expect(() => envService.getVariable('unknown' as any)).toThrow();
  });
});
