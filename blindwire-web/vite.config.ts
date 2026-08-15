import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [
    react(),
    {
      name: 'blindwire-dev-csp',
      transformIndexHtml(html, context) {
        if (!context.server) {
          return html;
        }
        return html.replace(
          "connect-src 'self' wss:",
          "connect-src 'self' ws: wss:",
        );
      },
    },
  ],
  server: {
    host: '127.0.0.1',
    port: 4173,
    strictPort: true,
  },
  test: {
    environment: 'jsdom',
    setupFiles: './tests/setup.ts',
    include: ['tests/**/*.test.ts', 'tests/**/*.test.tsx'],
  },
});
