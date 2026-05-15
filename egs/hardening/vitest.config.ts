import { defineConfig } from 'vitest/config';
import { resolve } from 'path';

export default defineConfig({
  test: {
    globals: false,
    environment: 'node',
  },
  resolve: {
    alias: {
      '@ncaos/core':      resolve(__dirname, '../core/src/index.ts'),
      '@ncaos/detection': resolve(__dirname, '../detection/src/index.ts'),
      '@ncaos/shell':     resolve(__dirname, '../shell/src/index.ts'),
    },
    extensions: ['.ts', '.js'],
  },
});
