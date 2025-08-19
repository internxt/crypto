function get(key: string): string | null {
  return localStorage.getItem(key);
}

function set(key: string, value: string): void {
  return localStorage.setItem(key, value);
}

function removeItem(key: string): void {
  localStorage.removeItem(key);
}

function exists(key: string): boolean {
  return !!localStorage.getItem(key);
}

function clear(): void {
  localStorage.clear();
}

const localStorageService = {
  set,
  get,
  removeItem,
  exists,
  clear,
};

export default localStorageService;

export interface LocalStorageService {
  set: (key: string, value: string) => void;
  get: (key: string) => string | null;
  removeItem: (key: string) => void;
  exists: (key: string) => boolean;
  clear: () => void;
}
