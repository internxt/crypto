function get(key: string): string | null {
  return sessionStorage.getItem(key);
}

function set(key: string, value: string): void {
  return sessionStorage.setItem(key, value);
}

function removeItem(key: string): void {
  sessionStorage.removeItem(key);
}

function exists(key: string): boolean {
  return !!sessionStorage.getItem(key);
}

function clear(): void {
  sessionStorage.clear();
}

const sessionStorageService = {
  set,
  get,
  removeItem,
  exists,
  clear,
};

export default sessionStorageService;

export interface SessionStorageService {
  set: (key: string, value: string) => void;
  get: (key: string) => string | null;
  removeItem: (key: string) => void;
  exists: (key: string) => boolean;
  clear: () => void;
}
