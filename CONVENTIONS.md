# Coding Conventions

<!-- This file documents project-specific coding standards for trustify-da-javascript-client. -->

## Language and Framework

- **Primary Language**: JavaScript (ES modules, `"type": "module"` in package.json)
- **TypeScript**: Configuration present but code is primarily JavaScript with JSDoc
- **Node.js**: Requires Node >= 20.0.0, npm >= 11.5.1
- **CLI**: `yargs` for command-line argument parsing
- **Parsing Libraries**: `fast-xml-parser`, `fast-toml`, `smol-toml`, `tree-sitter-requirements`

## Code Style

- **Linter**: ESLint with recommended config + editorconfig + import plugins
- **Indentation**: Tabs (4 spaces for YAML/Markdown)
- **Line endings**: LF
- **Max line length**: 100 (120 for Markdown)
- **Charset**: UTF-8, final newline, trim trailing whitespace
- **Import ordering** (ESLint enforced): builtin, external, internal, parent, sibling, index — alphabetical within groups
- **Strict equality**: `eqeqeq: ["warn", "always", {"null": "never"}]`
- **Curly braces**: Required (`curly: "warn"`)
- **No throw literals**: `no-throw-literal: "warn"`
- **No Prettier** — ESLint + EditorConfig handle formatting

## Naming Conventions

- **Classes**: PascalCase with underscore-separated language names (`Java_maven`, `Base_java`, `Javascript_npm`)
- **Files**: snake_case for providers (`base_java.js`, `javascript_npm.js`, `python_pip.js`)
- **Test files**: `*.test.js` suffix (`analysis.test.js`, `provider.test.js`)
- **Functions/Methods**: camelCase (`provideComponent()`, `provideStack()`, `validateLockFile()`)
- **Variables**: camelCase (`manifestPath`, `backendUrl`)
- **Constants**: UPPER_SNAKE_CASE (`ecosystem_maven`, `DEFAULT_WORKSPACE_DISCOVERY_IGNORE`)
- **Private class fields**: `#` prefix (`#manifest`, `#cmd`, `#ecosystem`)
- **Protected methods**: `_` prefix (`_lockFileName()`, `_cmdName()`, `_listCmdArgs()`)

## File Organization

```
src/
├── index.js                    # Main export
├── cli.js                      # CLI entry point
├── analysis.js                 # API request handling
├── provider.js                 # Provider matching logic
├── workspace.js                # Workspace discovery
├── tools.js                    # Utilities
├── sbom.js                     # SBOM handling
├── cyclone_dx_sbom.js          # CycloneDX SBOM generation
├── providers/                  # Ecosystem providers
│   ├── base_java.js
│   ├── base_javascript.js
│   ├── java_maven.js
│   ├── javascript_npm.js
│   ├── python_pip.js
│   ├── rust_cargo.js
│   └── processors/            # Specialized processors
├── license/                    # License detection
└── oci_image/                  # OCI image analysis

test/
├── analysis.test.js
├── provider.test.js
├── tools.test.js
└── providers/                  # Provider-specific tests
```

## Error Handling

- **Throw Error objects**: `throw new Error("message")`, `throw new TypeError("message")`
- **No custom error classes** — uses built-in `Error` and `TypeError`
- **HTTP errors**: Check `resp.status`, throw with status code and response text
- **Async errors**: Bubble up naturally via async/await (no blanket try-catch)
- **Validation errors**: Thrown early with descriptive context (manifest type, lock file)

## Testing Conventions

- **Framework**: Mocha with TDD UI (`suite()` / `test()`)
- **Assertions**: Chai with `expect()` syntax
- **Mocking**: Sinon for stubs; MSW (Mock Service Worker) for HTTP mocking
- **Module mocking**: `esmock` with experimental loader
- **Coverage**: C8 with 82% line coverage requirement
- **Test patterns**: `expect(res).to.deep.equal(...)`, `expect(() => ...).to.throw('message')`
- **Higher-order setup**: Functions like `interceptAndRun()` for test setup/teardown
- **Prefer real tool invocations over env var overrides**: Tests should call the actual ecosystem tools (pip, uv, poetry, mvn, npm, etc.) rather than injecting pre-recorded output via `TRUSTIFY_DA_*` environment variables. The CI environment has these tools available. Env var overrides (`TRUSTIFY_DA_PIP_REPORT`, `TRUSTIFY_DA_UV_EXPORT`, etc.) exist for users who lack the tool locally, but tests should exercise the real tool path to catch integration issues.
- **Golden SBOM files for every test fixture**: Every provider test fixture directory must include `expected_stack_sbom.json` and `expected_component_sbom.json` golden files. Tests must use the `SBOM_CASES` pattern to do a full `deep.equal` comparison of the provider output against these golden files. Manual partial assertions (e.g. checking a single component name) are not a substitute — they may be added as supplementary tests but never as the only verification for a fixture.

## Commit Messages

- Likely Conventional Commits format
- DCO (Developer Certificate of Origin) required
- Semantic versioning (`0.3.0` in package.json)

## Test Fixtures

- **Dependabot suppression**: Test fixture directories contain intentionally pinned (sometimes vulnerable) dependencies. When adding a new test fixture directory with a manifest file, review `.github/dependabot.yml` to ensure the new path is covered. Non-npm ecosystems are suppressed via root-level `ignore: [{dependency-name: "*"}]` entries. npm fixtures use per-directory entries with `/**` globs; add the parent directory if a new npm/pnpm/yarn fixture tree is introduced.

## Dependencies

- **Package manager**: npm with `package-lock.json`
- **Module system**: ES modules with explicit `.js` extensions in relative imports
- **Import convention**: `import fs from 'node:fs'` (node: protocol for built-ins)
- **Environment variables**: Prefixed with `TRUSTIFY_DA_` (e.g., `TRUSTIFY_DA_MVN_PATH`, `TRUSTIFY_DA_TOKEN`, `TRUSTIFY_DA_DEBUG`)
- **Multi-ecosystem support**: npm, pnpm, yarn, Maven, Gradle, pip, cargo, Go modules, Docker/Podman
