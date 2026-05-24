import { defineConfig } from 'vitest/config';
import { resolve } from 'path';

export default defineConfig({
  test: {
    globals: false,
    environment: 'node',
  },
  plugins: [
    {
      name: 'rewrite-js-to-ts',
      resolveId(id, importer) {
        if (importer && id.endsWith('.js')) {
          const tsPath = id.slice(0, -3) + '.ts';
          const dir = importer.includes('shell/src')
            ? importer.substring(0, importer.lastIndexOf('/'))
            : null;
          if (dir) {
            return resolve(dir, tsPath);
          }
        }
        return null;
      },
    },
  ],
  resolve: {
    alias: {
      '@ncaos/core': resolve(__dirname, '../core/src/index.ts'),
      '@ncaos/shell': resolve(__dirname, '../shell/src/index.ts'),
    },
  },
});