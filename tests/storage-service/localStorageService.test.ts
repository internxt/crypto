import { describe, it, expect, vi, beforeEach } from 'vitest';
import localStorageService from '../../src/storage-service/localStorageService';

const mockLocalStorageService = {
  getItem: vi.fn(),
  setItem: vi.fn(),
  removeItem: vi.fn(),
  clear: vi.fn(),
};

Object.defineProperty(globalThis, 'localStorage', {
  value: mockLocalStorageService,
  writable: true,
});

describe('sessionStorageService', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('get', () => {
    it('should return value from sessionStorage', () => {
      mockLocalStorageService.getItem.mockReturnValue('test-value');

      const result = localStorageService.get('test-key');

      expect(mockLocalStorageService.getItem).toHaveBeenCalledWith('test-key');
      expect(result).toBe('test-value');
    });

    it('should return null when key does not exist', () => {
      mockLocalStorageService.getItem.mockReturnValue(null);

      const result = localStorageService.get('non-existent-key');

      expect(result).toBeNull();
    });
  });

  describe('set', () => {
    it('should call sessionStorage.setItem with key and value', () => {
      localStorageService.set('test-key', 'test-value');

      expect(mockLocalStorageService.setItem).toHaveBeenCalledWith('test-key', 'test-value');
    });
  });

  describe('removeItem', () => {
    it('should call sessionStorage.removeItem with key', () => {
      localStorageService.removeItem('test-key');

      expect(mockLocalStorageService.removeItem).toHaveBeenCalledWith('test-key');
    });
  });

  describe('exists', () => {
    it('should return true when key exists', () => {
      mockLocalStorageService.getItem.mockReturnValue('some-value');

      const result = localStorageService.exists('test-key');

      expect(result).toBe(true);
    });

    it('should return false when key does not exist', () => {
      mockLocalStorageService.getItem.mockReturnValue(null);

      const result = localStorageService.exists('test-key');

      expect(result).toBe(false);
    });

    it('should return false for empty string value', () => {
      mockLocalStorageService.getItem.mockReturnValue('');

      const result = localStorageService.exists('test-key');

      expect(result).toBe(false);
    });
  });

  describe('clear', () => {
    it('should call sessionStorage.clear', () => {
      localStorageService.clear();

      expect(mockLocalStorageService.clear).toHaveBeenCalledWith();
    });
  });
});
