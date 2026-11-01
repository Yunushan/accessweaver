const { defineConfig } = require('@playwright/test');
const path = require('node:path');
module.exports = defineConfig({
  testDir: '.', testMatch: 'desktop.spec.cjs',
  timeout: 45_000, globalTimeout: 10 * 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: false, workers: 1, retries: 0, forbidOnly: !!process.env.CI,
  outputDir: path.resolve(__dirname, '../../build/browser-results/artifacts'),
  reporter: [['list'], ['json', { outputFile: path.resolve(__dirname, '../../build/browser-results/results.json') }]],
  // Traces contain session headers and private-launch URLs. Keep them disabled.
  use: { headless: true, trace: 'off', screenshot: 'only-on-failure', viewport: { width: 1280, height: 900 } },
  projects: [
    { name: 'chromium', use: { browserName: 'chromium', ...(process.env.PW_BROWSER_CHANNEL ? {channel:process.env.PW_BROWSER_CHANNEL} : {}) } },
    { name: 'firefox', use: { browserName: 'firefox' } },
    { name: 'webkit', use: { browserName: 'webkit' } },
  ],
});
