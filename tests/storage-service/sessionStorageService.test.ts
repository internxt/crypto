import { describe, it, expect, vi, beforeEach } from 'vitest';
import sessionStorageService from '../../src/storage-service/sessionStorageService';

const mockSessionStorage = {
  getItem: vi.fn(),
  setItem: vi.fn(),
  removeItem: vi.fn(),
  clear: vi.fn(),
};

Object.defineProperty(globalThis, 'sessionStorage', {
  value: mockSessionStorage,
  writable: true,
});

describe('sessionStorageService', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('get', () => {
    it('should return value from sessionStorage', () => {
      mockSessionStorage.getItem.mockReturnValue('test-value');

      const result = sessionStorageService.get('test-key');

      expect(mockSessionStorage.getItem).toHaveBeenCalledWith('test-key');
      expect(result).toBe('test-value');
    });

    it('should return null when key does not exist', () => {
      mockSessionStorage.getItem.mockReturnValue(null);

      const result = sessionStorageService.get('non-existent-key');

      expect(result).toBeNull();
    });
  });

  describe('set', () => {
    it('should call sessionStorage.setItem with key and value', () => {
      sessionStorageService.set('test-key', 'test-value');

      expect(mockSessionStorage.setItem).toHaveBeenCalledWith('test-key', 'test-value');
    });
  });

  describe('removeItem', () => {
    it('should call sessionStorage.removeItem with key', () => {
      sessionStorageService.removeItem('test-key');

      expect(mockSessionStorage.removeItem).toHaveBeenCalledWith('test-key');
    });
  });

  describe('exists', () => {
    it('should return true when key exists', () => {
      mockSessionStorage.getItem.mockReturnValue('some-value');

      const result = sessionStorageService.exists('test-key');

      expect(result).toBe(true);
    });

    it('should return false when key does not exist', () => {
      mockSessionStorage.getItem.mockReturnValue(null);

      const result = sessionStorageService.exists('test-key');

      expect(result).toBe(false);
    });

    it('should return false for empty string value', () => {
      mockSessionStorage.getItem.mockReturnValue('');

      const result = sessionStorageService.exists('test-key');

      expect(result).toBe(false);
    });
  });

  describe('clear', () => {
    it('should call sessionStorage.clear', () => {
      sessionStorageService.clear();

      expect(mockSessionStorage.clear).toHaveBeenCalledWith();
    });
  });
});
