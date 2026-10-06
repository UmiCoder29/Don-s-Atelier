import { defineConfig } from 'vitest/config';
import path from 'path';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    testTimeout: 30000,
    hookTimeout: 30000,
    fileParallelism: false,
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
    include: ['tests/**/*.test.ts'],
  },
});
