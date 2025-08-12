import { defineConfig } from "vite";

export default defineConfig({
  build: {
    lib: {
      entry: "src/index.ts",
      formats: ["es", "cjs"],
      fileName: (format) => `index.${format === "es" ? "mjs" : "js"}`,
    },
    rollupOptions: {
      external: [
        "buffer",
        "hash-wasm",
        "uuid",
        "@noble/post-quantum",
        "minisearch",
      ],
      output: {
        globals: {
          buffer: "Buffer",
          "hash-wasm": "hashWasm",
          uuid: "uuid",
          "@noble/post-quantum": "noblePostQuantum",
          minisearch: "MiniSearch",
        },
      },
    },
    sourcemap: true,
    target: "es2020",
  },
  assetsInclude: ["**/*.wasm"],
  optimizeDeps: {
    exclude: ["blake3"],
  },
  server: {
    fs: {
      allow: [".."],
    },
  },
  define: {
    global: "globalThis",
  },
});
