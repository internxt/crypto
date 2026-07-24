import { defineConfig, type UserConfig } from 'tsdown';

const entry = {
  index: 'src/index.ts',
  'asymmetric-crypto': 'src/asymmetric-crypto/index.ts',
  'symmetric-crypto': 'src/symmetric-crypto/index.ts',
  'post-quantum-crypto': 'src/post-quantum-crypto/index.ts',
  hash: 'src/hash/index.ts',
  'derive-key': 'src/derive-key/index.ts',
  'derive-password': 'src/derive-password/index.ts',
  'email-crypto': 'src/email-crypto/index.ts',
  'keystore-crypto': 'src/keystore-crypto/index.ts',
  'storage-service': 'src/storage-service/index.ts',
  utils: 'src/utils/index.ts',
  types: 'src/types.ts',
  constants: 'src/constants.ts',
};

const shared: Partial<UserConfig> = {
  platform: 'browser',
  format: ['esm', 'cjs'],
  sourcemap: true,
  treeshake: true,
  dts: true,
  target: false,
};

export default defineConfig([
  {
    ...shared,
    entry,
    outDir: 'dist',
    clean: true,
    deps: {
    onlyBundle: ['hash-wasm'],
    alwaysBundle: ['hash-wasm'],
  },
  },
  {
    ...shared,
    entry,
    outDir: 'dist/react-native',
    clean: false,
    inputOptions: {
      resolve: {
        extensions: ['.native.ts', '.native.tsx', '.ts', '.tsx', '.mjs', '.js', '.jsx', '.json'],
      },
    },
  },
]);