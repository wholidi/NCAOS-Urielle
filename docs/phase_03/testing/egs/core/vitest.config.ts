import { defineConfig } from 'vitest/config';
import { resolve } from 'path';

export default defineConfig({
  test: {
    globals: false,
    environment: 'node',
    alias: {
      '../../src/': resolve(__dirname, './src/') + '/',
      '../src/': resolve(__dirname, './src/') + '/',
    },
  },
});