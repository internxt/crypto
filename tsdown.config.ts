import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'asymmetric-crypto': 'src/asymmetric-crypto/index.ts',
    'symmetric-crypto': 'src/symmetric-crypto/index.ts',
    'post-quantum-crypto': 'src/post-quantum-crypto/index.ts',
    hash: 'src/hash/index.ts',
    'derive-key': 'src/derive-key/index.ts',
    'email-crypto': 'src/email-crypto/index.ts',
    'keystore-crypto': 'src/keystore-crypto/index.ts',
    'keystore-service': 'src/keystore-service/index.ts',
    'email-search': 'src/email-search/index.ts',
    'storage-service': 'src/storage-service/index.ts',
    utils: 'src/utils/index.ts',
    types: 'src/types.ts',
    constants: 'src/constants.ts',
  },
  platform: 'browser',
  format: ['esm', 'cjs'],
  sourcemap: true,
  clean: true,
  treeshake: true,
  outDir: 'dist',
  dts: true,
  noExternal: ['hash-wasm'],
  target: false,
});
