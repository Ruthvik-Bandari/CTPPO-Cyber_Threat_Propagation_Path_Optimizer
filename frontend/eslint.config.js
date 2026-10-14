import js from "@eslint/js";
import jsxA11y from "eslint-plugin-jsx-a11y";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["node_modules", "dist"] },
  js.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  reactHooks.configs.flat.recommended,
  jsxA11y.flatConfigs.strict,
  {
    languageOptions: {
      globals: globals.browser,
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
    rules: {
      "@typescript-eslint/restrict-template-expressions": ["error", { allowNumber: true }],
      // Scrollable regions (code, diffs) must be keyboard-reachable (WCAG 2.1.1).
      "jsx-a11y/no-noninteractive-tabindex": ["error", { tags: [], roles: ["tabpanel", "region"] }],
      "jsx-a11y/label-has-associated-control": ["error", { depth: 3 }],
    },
  },
  { files: ["eslint.config.js"], ...tseslint.configs.disableTypeChecked },
);
