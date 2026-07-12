import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    coverage: {
      provider: "v8",
      // Tests import the compiled output (npm test builds first), so we
      // instrument dist/ and let the emitted sourcemaps remap to src/*.ts.
      include: ["dist/**/*.js"],
      // cli.js runs main() at import time and is exercised end-to-end via
      // `skopecreep redact-check`, not unit tests — it would sit at 0% and
      // poison the thresholds.
      exclude: ["dist/cli.js"],
      reporter: ["text", "html"],
      thresholds: {
        // Measured 2026-07: statements 78 / branches 64 / functions 91 / lines 81.
        // Thresholds sit ~5 points below measured; raise them as coverage grows.
        lines: 75,
        statements: 73,
        functions: 85,
        branches: 58,
      },
    },
  },
});
