import fs from 'node:fs'
import path from 'node:path'

import { load as yamlLoad } from 'js-yaml'

/**
 * @typedef {{
 *   'backend-url'?: string,
 *   providers?: string[] | string,
 *   sources?: string[] | string,
 *   remediation?: object,
 *   check?: object,
 *   sbom?: object,
 *   [key: string]: unknown
 * }} FileConfig
 */

/**
 * @typedef {{
 *   backendUrl: string | null,
 *   providers: string[],
 *   sources: string[],
 *   groupBy: string,
 *   remediation: object,
 *   check: object,
 *   sbom: object
 * }} ResolvedConfig
 */

/** Name of the project config file discovered by walking up the directory tree. */
export const CONFIG_FILENAME = '.trustify-da.yml'

/**
 * Walks up from `startPath` looking for a `.trustify-da.yml` file, similar to
 * how `.eslintrc` discovery works. If `startPath` points at a file, discovery
 * begins in its containing directory.
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
		const candidate = path.join(dir, CONFIG_FILENAME)
		if (fs.existsSync(candidate)) {
			return candidate
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
	return doc && typeof doc === 'object' ? doc : {}
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
	const file = fileConfig || {}
	const cli = cliFlags || {}
	const env = envVars || {}
	const groupBy = first(cli.groupBy, env.TRUSTIFY_DA_GROUP_BY, file.remediation?.['group-by']) ?? 'dependency'
	if (!['dependency', 'bundle'].includes(groupBy)) {
		throw new Error(`Invalid group-by value "${groupBy}". Expected dependency or bundle.`)
	}
	return {
		backendUrl: first(cli.backendUrl, env.TRUSTIFY_DA_BACKEND_URL, file['backend-url']) ?? null,
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
