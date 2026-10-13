import fs from 'node:fs'
import path from 'node:path'

import { load as yamlLoad } from 'js-yaml'

/** @typedef {{'group-by'?: 'dependency' | 'bundle', exclude?: string[], labels?: string[], 'branch-prefix'?: string, [key: string]: unknown}} RemediationConfig */

/** @typedef {{ critical?: number, high?: number, 'license-conflicts'?: number, [key: string]: unknown }} FailOnConfig */
/** @typedef {{ 'fail-on'?: FailOnConfig, [key: string]: unknown }} CheckConfig */
/** @typedef {{ format?: string, targets?: string[], [key: string]: unknown }} SbomConfig */

/** @typedef {{'backend-url'?: string, providers?: string[] | string, sources?: string[] | string, remediation?: RemediationConfig, check?: CheckConfig, sbom?: SbomConfig, [key: string]: unknown}} FileConfig */

/**
 * @typedef {{
 *   backendUrl: string | null,
 *   backendUrlSource: 'cli' | 'environment' | 'file' | 'default',
 *   providers: string[],
 *   sources: string[],
 *   groupBy: string,
 *   remediation: object,
 *   check: object,
 *   sbom: object
 * }} ResolvedConfig
 */

/** Config file names discovered by walking up the directory tree, in precedence order. */
export const CONFIG_FILENAMES = ['.trustify-da.yml', '.trustify-da.yaml']

function isMapping(value) {
	if (value == null || typeof value !== 'object' || Array.isArray(value)) {
		return false
	}
	const prototype = Object.getPrototypeOf(value)
	return prototype === Object.prototype || prototype == null
}

function assertMapping(value, field, source) {
	if (!isMapping(value)) {
		throw new Error(`Invalid config file ${source}: ${field} must be a mapping`)
	}
}

function assertString(value, field, source) {
	if (typeof value !== 'string') {
		throw new Error(`Invalid config file ${source}: ${field} must be a string`)
	}
}

function assertStringArray(value, field, source) {
	if (!Array.isArray(value) || value.some(item => typeof item !== 'string')) {
		throw new Error(`Invalid config file ${source}: ${field} must be an array of strings`)
	}
}

function assertStringOrArray(value, field, source) {
	if (typeof value !== 'string') {
		assertStringArray(value, field, source)
	}
}

/**
 * Validates all fields in the initial configuration schema. Unknown fields are preserved.
 * @param {unknown} config
 * @param {string} [source]
 * @returns {FileConfig}
 */
function validateConfig(config, source = '<config>') {
	assertMapping(config, 'root', source)
	if (config['backend-url'] !== undefined) {
		assertString(config['backend-url'], 'backend-url', source)
	}
	if (config.providers !== undefined) {
		assertStringOrArray(config.providers, 'providers', source)
	}
	if (config.sources !== undefined) {
		assertStringOrArray(config.sources, 'sources', source)
	}
	if (config.remediation !== undefined) {
		assertMapping(config.remediation, 'remediation', source)
		const remediation = config.remediation
		if (remediation['group-by'] !== undefined && !['dependency', 'bundle'].includes(remediation['group-by'])) {
			throw new Error(`Invalid config file ${source}: remediation.group-by must be dependency or bundle`)
		}
		if (remediation.exclude !== undefined) {
			assertStringArray(remediation.exclude, 'remediation.exclude', source)
		}
		if (remediation.labels !== undefined) {
			assertStringArray(remediation.labels, 'remediation.labels', source)
		}
		if (remediation['branch-prefix'] !== undefined) {
			assertString(remediation['branch-prefix'], 'remediation.branch-prefix', source)
		}
	}
	if (config.check !== undefined) {
		assertMapping(config.check, 'check', source)
		if (config.check['fail-on'] !== undefined) {
			assertMapping(config.check['fail-on'], 'check.fail-on', source)
			for (const field of ['critical', 'high', 'license-conflicts']) {
				const value = config.check['fail-on'][field]
				if (value !== undefined && (typeof value !== 'number' || !Number.isFinite(value))) {
					throw new Error(`Invalid config file ${source}: check.fail-on.${field} must be a finite number`)
				}
			}
		}
	}
	if (config.sbom !== undefined) {
		assertMapping(config.sbom, 'sbom', source)
		if (config.sbom.format !== undefined) {
			assertString(config.sbom.format, 'sbom.format', source)
		}
		if (config.sbom.targets !== undefined) {
			assertStringArray(config.sbom.targets, 'sbom.targets', source)
		}
	}
	return config
}

/**
 * Walks up from `startPath` looking for a `.trustify-da.yml` (or `.yaml`) file,
 * similar to how `.eslintrc` discovery works. If `startPath` points at a file,
 * discovery begins in its containing directory. Within a directory, `.yml` takes
 * precedence over `.yaml`.
 * @param {string} startPath - manifest file or directory to start the search from
 * @returns {string | null} absolute path to the config file, or null if none found
 */
function findConfigFile(startPath) {
	let dir = path.resolve(startPath || '.')
	try {
		if (fs.statSync(dir).isFile()) {
			dir = path.dirname(dir)
		}
	} catch {
		// startPath may not exist yet — walk up from its resolved location anyway
	}
	// Walk up until the filesystem root (where dirname(dir) === dir)
	for (;;) {
		for (const name of CONFIG_FILENAMES) {
			const candidate = path.join(dir, name)
			try {
				if (fs.statSync(candidate).isFile()) {
					return candidate
				}
			} catch {
				// Ignore inaccessible or disappearing candidates and continue discovery.
			}
		}
		const parent = path.dirname(dir)
		if (parent === dir) {
			return null
		}
		dir = parent
	}
}

/**
 * Discovers and parses `.trustify-da.yml` by walking up from `startPath`.
 * A missing config file is not an error — an empty object is returned so callers
 * can fall back to defaults.
 * @param {string} [startPath] - manifest file or directory to start the search from
 * @returns {FileConfig} the parsed config object, or `{}` when no file is found
 * @throws {Error} when the config file exists but contains malformed YAML
 */
export function loadConfig(startPath) {
	const configPath = findConfigFile(startPath)
	if (!configPath) {
		return {}
	}
	const content = fs.readFileSync(configPath, 'utf-8')
	let doc
	try {
		doc = yamlLoad(content)
	} catch (err) {
		throw new Error(`Failed to parse config file ${configPath}: ${err.message}`)
	}
	return doc == null ? {} : validateConfig(doc, configPath)
}

/**
 * Normalizes a providers/sources value to an array of trimmed strings. Accepts
 * either a YAML array (`[redhat, osv]`) or a comma-separated string (`redhat,osv`).
 * @param {string[] | string | undefined | null} value
 * @returns {string[]}
 */
function toArray(value) {
	if (Array.isArray(value)) {
		return value.filter(v => typeof v === 'string' && v.trim()).map(v => v.trim())
	}
	if (typeof value === 'string') {
		return value.split(',').map(v => v.trim()).filter(Boolean)
	}
	return []
}

/**
 * Returns the first argument that is neither undefined nor null.
 * @param {...unknown} values
 * @returns {unknown}
 */
function first(...values) {
	return values.find(v => v != null)
}

/**
 * Merges config sources with precedence: CLI flag > environment variable
 * (`TRUSTIFY_DA_*`) > config file > hardcoded default. Providers and sources are
 * normalized to arrays regardless of whether the source used a YAML array or a
 * comma-separated string.
 * @param {FileConfig} [fileConfig={}] - values parsed from `.trustify-da.yml`
 * @param {{ providers?: string, sources?: string, groupBy?: string, backendUrl?: string }} [cliFlags={}]
 * @param {{ [key: string]: string | undefined }} [envVars={}] - typically `process.env`
 * @returns {ResolvedConfig} the resolved, typed config object
 */
export function mergeConfig(fileConfig = {}, cliFlags = {}, envVars = {}) {
	const file = validateConfig(fileConfig || {})
	const cli = cliFlags || {}
	const env = envVars || {}
	let backendUrl = null
	let backendUrlSource = 'default'
	if (cli.backendUrl != null) {
		backendUrl = cli.backendUrl
		backendUrlSource = 'cli'
	} else if (env.TRUSTIFY_DA_BACKEND_URL != null) {
		backendUrl = env.TRUSTIFY_DA_BACKEND_URL
		backendUrlSource = 'environment'
	} else if (file['backend-url'] != null) {
		backendUrl = file['backend-url']
		backendUrlSource = 'file'
	}
	const groupBy = first(cli.groupBy, env.TRUSTIFY_DA_GROUP_BY, file.remediation?.['group-by']) ?? 'dependency'
	if (!['dependency', 'bundle'].includes(groupBy)) {
		throw new Error(`Invalid group-by value "${groupBy}". Expected dependency or bundle.`)
	}
	return {
		backendUrl,
		backendUrlSource,
		providers: toArray(first(cli.providers, env.TRUSTIFY_DA_PROVIDERS, file.providers)),
		sources: toArray(first(cli.sources, env.TRUSTIFY_DA_SOURCES, file.sources)),
		groupBy,
		remediation: file.remediation ?? {},
		check: file.check ?? {},
		sbom: file.sbom ?? {},
	}
}

/**
 * Loads and merges the project configuration for a target path.
 * @param {string} [startPath] - manifest file or directory to start discovery from
 * @param {{ providers?: string, sources?: string, groupBy?: string, backendUrl?: string }} [cliFlags={}] - explicit options
 * @param {{ [key: string]: string | undefined }} [envVars={}] - typically `process.env`
 * @returns {ResolvedConfig} the resolved, typed config object
 */
export function resolveConfig(startPath, cliFlags = {}, envVars = {}) {
	return mergeConfig(loadConfig(startPath), cliFlags, envVars)
}
