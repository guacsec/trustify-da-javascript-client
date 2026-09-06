import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { expect } from 'chai'

import { loadConfig, mergeConfig, resolveConfig, CONFIG_FILENAME } from '../src/config.js'

const testDir = path.dirname(fileURLToPath(import.meta.url))
const validDir = path.join(testDir, 'fixtures', 'config', 'valid')
const invalidDir = path.join(testDir, 'fixtures', 'config', 'invalid')

/**
 * Creates a fresh temporary directory outside the repository tree so config
 * discovery walks up to the filesystem root without finding a real config file.
 * @returns {string} absolute path to the temp directory
 */
function makeTempDir() {
	return fs.mkdtempSync(path.join(os.tmpdir(), 'trustify-da-config-'))
}

suite('loadConfig', () => {
	test('parses a valid config file and exposes all sections', () => {
		// Given a directory containing a valid .trustify-da.yml
		// When loading the config
		const config = loadConfig(validDir)

		// Then top-level and nested sections are accessible
		expect(config['backend-url']).to.equal('https://da.example.com')
		expect(config.providers).to.deep.equal(['redhat', 'lightwell'])
		expect(config.sources).to.deep.equal(['osv'])
		expect(config.remediation['group-by']).to.equal('bundle')
		expect(config.remediation.exclude).to.deep.equal(['pkg:maven/com.example/legacy-lib'])
		expect(config.check['fail-on']).to.deep.equal({ critical: 0, high: 10, 'license-conflicts': 0 })
		expect(config.sbom).to.deep.equal({ format: 'cyclonedx', targets: ['artifact', 'trustify'] })
	})

	test('parses nested remediation, check, and sbom sections correctly', () => {
		// Given a valid config file
		const config = loadConfig(validDir)

		// Then each nested section retains its structure
		expect(config.remediation.labels).to.deep.equal(['trustify-da', 'security'])
		expect(config.remediation['branch-prefix']).to.equal('trustify-da/')
		expect(config.check['fail-on'].high).to.equal(10)
		expect(config.sbom.targets).to.deep.equal(['artifact', 'trustify'])
	})

	test('returns an empty object when no config file is found', () => {
		// Given a temp directory with no config file anywhere up the tree
		const tmp = makeTempDir()
		try {
			// When loading the config
			// Then an empty object (defaults) is returned instead of throwing
			expect(loadConfig(tmp)).to.deep.equal({})
		} finally {
			fs.rmSync(tmp, { recursive: true, force: true })
		}
	})

	test('returns an empty object for a non-existent path', () => {
		// Given a path that does not exist
		const tmp = makeTempDir()
		try {
			// When loading the config from a missing child path
			// Then discovery still walks up gracefully and returns defaults
			expect(loadConfig(path.join(tmp, 'does', 'not', 'exist'))).to.deep.equal({})
		} finally {
			fs.rmSync(tmp, { recursive: true, force: true })
		}
	})

	test('accepts a file path and discovers the config in its directory', () => {
		// Given the config file path itself (a file, not a directory)
		const filePath = path.join(validDir, CONFIG_FILENAME)

		// When loading the config
		// Then discovery starts from the containing directory and finds it
		expect(loadConfig(filePath).providers).to.deep.equal(['redhat', 'lightwell'])
	})

	test('throws a descriptive error for malformed YAML', () => {
		// Given a directory with a malformed .trustify-da.yml
		// When loading the config
		// Then a descriptive error naming the file is thrown
		expect(() => loadConfig(invalidDir)).to.throw(/Failed to parse config file/)
	})

	test('discovers a config file in a parent directory (walks up)', () => {
		// Given a config file at the top of a nested temp tree
		const tmp = makeTempDir()
		try {
			fs.writeFileSync(path.join(tmp, CONFIG_FILENAME), 'providers: [redhat]\n')
			const deep = path.join(tmp, 'a', 'b', 'c')
			fs.mkdirSync(deep, { recursive: true })

			// When loading from a deeply nested subdirectory
			// Then discovery walks up and finds the ancestor config
			expect(loadConfig(deep).providers).to.deep.equal(['redhat'])
		} finally {
			fs.rmSync(tmp, { recursive: true, force: true })
		}
	})
})

suite('mergeConfig', () => {
	const fileConfig = {
		'backend-url': 'https://file.example.com',
		providers: ['redhat', 'lightwell'],
		sources: ['osv'],
		remediation: { 'group-by': 'bundle' },
		check: { 'fail-on': { critical: 0 } },
		sbom: { format: 'cyclonedx' },
	}

	test('uses file config values when no CLI flags or env vars are set', () => {
		// Given only a file config
		const merged = mergeConfig(fileConfig, {}, {})

		// Then file values are used and normalized to arrays
		expect(merged.providers).to.deep.equal(['redhat', 'lightwell'])
		expect(merged.sources).to.deep.equal(['osv'])
		expect(merged.groupBy).to.equal('bundle')
		expect(merged.backendUrl).to.equal('https://file.example.com')
	})

	test('CLI flags override config file values', () => {
		// Given a file config and a CLI flag for providers
		const merged = mergeConfig(fileConfig, {
			backendUrl: 'https://cli.example.com',
			providers: 'snyk,osv',
			groupBy: 'dependency',
		}, {})

		// Then the CLI flag wins over the file value
		expect(merged.providers).to.deep.equal(['snyk', 'osv'])
		expect(merged.groupBy).to.equal('dependency')
		expect(merged.backendUrl).to.equal('https://cli.example.com')
	})

	test('CLI flags override environment variables and config file', () => {
		// Given a file config, environment variables, and CLI flags
		const env = { TRUSTIFY_DA_PROVIDERS: 'env-provider', TRUSTIFY_DA_SOURCES: 'env-source' }

		// When only environment variables are set, they override the file value
		const envOnly = mergeConfig(fileConfig, {}, env)
		expect(envOnly.providers).to.deep.equal(['env-provider'])
		expect(envOnly.sources).to.deep.equal(['env-source'])

		// When both a CLI flag and environment variable are set, the CLI flag wins
		const withCli = mergeConfig(fileConfig, { providers: 'cli-provider' }, env)
		expect(withCli.providers).to.deep.equal(['cli-provider'])
		expect(withCli.sources).to.deep.equal(['env-source'])
	})

	test('falls back to hardcoded defaults with empty inputs', () => {
		// Given no config at all
		const merged = mergeConfig()

		// Then empty collections and the default group-by are returned
		expect(merged.providers).to.deep.equal([])
		expect(merged.sources).to.deep.equal([])
		expect(merged.groupBy).to.equal('dependency')
		expect(merged.backendUrl).to.equal(null)
	})

	test('rejects an invalid group-by value', () => {
		// Given a group-by value outside the supported strategies
		// When merging configuration
		// Then a descriptive validation error is thrown
		expect(() => mergeConfig({}, { groupBy: 'invalid' }, {}))
			.to.throw('Invalid group-by value "invalid"')
	})

	test('CLI empty string overrides environment variable for providers', () => {
		// Given an environment variable and an explicitly empty CLI flag
		const env = { TRUSTIFY_DA_PROVIDERS: 'env-provider' }
		const merged = mergeConfig({}, { providers: '' }, env)

		// Then the empty CLI value wins over the environment value
		expect(merged.providers).to.deep.equal([])
	})

	test('CLI empty string overrides environment variable for backendUrl', () => {
		// Given an environment variable and an explicitly empty CLI flag
		const env = { TRUSTIFY_DA_BACKEND_URL: 'https://env.example.com' }
		const merged = mergeConfig({}, { backendUrl: '' }, env)

		// Then the empty CLI value wins over the environment value
		expect(merged.backendUrl).to.equal('')
	})
})

suite('resolveConfig', () => {
	test('loads project config and returns resolved command values', () => {
		// Given a project path containing .trustify-da.yml
		// When resolving command configuration
		const resolved = resolveConfig(validDir, {}, {})

		// Then supported command values are available in their runtime form
		expect(resolved.providers).to.deep.equal(['redhat', 'lightwell'])
		expect(resolved.sources).to.deep.equal(['osv'])
		expect(resolved.groupBy).to.equal('bundle')
	})

	test('applies environment overrides while resolving project config', () => {
		// Given project defaults and environment overrides
		const env = {
			TRUSTIFY_DA_PROVIDERS: 'env-provider',
			TRUSTIFY_DA_GROUP_BY: 'dependency',
		}

		// When resolving command configuration
		const resolved = resolveConfig(validDir, {}, env)

		// Then environment values override the project defaults
		expect(resolved.providers).to.deep.equal(['env-provider'])
		expect(resolved.groupBy).to.equal('dependency')
	})

	test('does not fall back to the file when an environment value is empty', () => {
		// Given a file backend URL and an explicitly empty environment override
		const env = { TRUSTIFY_DA_BACKEND_URL: '' }

		// When resolving command configuration
		const resolved = resolveConfig(validDir, {}, env)

		// Then the explicit empty value is retained
		expect(resolved.backendUrl).to.equal('')
	})
})
