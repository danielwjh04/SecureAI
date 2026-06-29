import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    environment: 'jsdom',
    environmentOptions: {
      jsdom: {
        url: 'https://github.com/danielwjh04/SecureAI',
      },
    },
    include: ['tests/**/*.test.ts'],
  },
})
