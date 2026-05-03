import { defineConfig } from 'vitest/config';
import { resolve } from 'path';

export default defineConfig({
  test: {
    globals: false,
    environment: 'node',
  },
  resolve: {
    alias: {
      '@ncaos/core': resolve(__dirname, '../core/src/index.ts'),
    },
    extensions: ['.ts', '.js'],
  },
});
