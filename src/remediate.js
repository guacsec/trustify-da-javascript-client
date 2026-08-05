import fs from 'node:fs'
import path from 'node:path'

import analysis from './analysis.js'
import { availableProviders, match } from './provider.js'
import { extractRemediations } from './remediation.js'
import { generateReport } from './remediation_report.js'
import { getCustom } from './tools.js'
import { updateMavenVersions } from './updaters/maven_updater.js'
import { updateTomlVersions } from './updaters/toml_updater.js'

/**
 * Supported manifest file patterns and their corresponding updater functions.
 * @type {Array<{test: function(string): boolean, updater: function(string, Array): object, label: string}>}
 */
const MANIFEST_TYPES = [
	{
		test: (basename) => basename === 'pom.xml',
		updater: updateMavenVersions,
		label: 'maven',
	},
	{
		test: (basename) => basename.endsWith('.versions.toml') || basename === 'libs.versions.toml',
		updater: updateTomlVersions,
		label: 'toml',
	},
]

/**
 * Discovers supported manifest files recursively within a directory.
 * @param {string} dirPath - absolute path to the directory
 * @returns {string[]} array of absolute paths to supported manifest files
 */
function discoverManifests(dirPath) {
	const manifests = []

	function walk(dir) {
		const entries = fs.readdirSync(dir, { withFileTypes: true })
		for (const entry of entries) {
			if (entry.name === 'node_modules' || entry.name === '.git') {
				continue
			}
			const fullPath = path.join(dir, entry.name)
			if (entry.isDirectory()) {
				walk(fullPath)
			} else if (getManifestType(entry.name)) {
				manifests.push(fullPath)
			}
		}
	}

	walk(dirPath)
	return manifests
}

/**
 * Returns the manifest type descriptor for a given filename, or null if unsupported.
 * @param {string} basename - the file name to check
 * @returns {{test: function, updater: function, label: string}|null}
 */
function getManifestType(basename) {
	return MANIFEST_TYPES.find(t => t.test(basename)) || null
}

/**
 * Resolves the Trustify DA backend URL from environment or options.
 * @param {object} opts
 * @returns {string}
 * @throws {Error} if TRUSTIFY_DA_BACKEND_URL is unset
 */
function resolveBackendUrl(opts) {
	const url = getCustom('TRUSTIFY_DA_BACKEND_URL', null, opts)
	if (!url) {
		throw new Error('TRUSTIFY_DA_BACKEND_URL is unset')
	}
	return url
}

/**
 * Orchestrates the full remediation pipeline for a single manifest or directory:
 * discover manifests → scan via DA backend → extract remediations → apply or preview.
 *
 * @param {string} targetPath - path to a manifest file or directory
 * @param {object} [options]
 * @param {boolean} [options.dryRun=false] - preview changes without modifying files
 * @param {boolean} [options.apply=false] - apply changes to manifest files
 * @param {string} [options.providers] - comma-separated provider list
 * @param {string} [options.sources] - comma-separated source list
 * @param {'dependency'|'bundle'} [options.groupBy='dependency'] - report grouping strategy
 * @returns {Promise<{exitCode: number, output: string}>}
 */
export async function runRemediation(targetPath, options = {}) {
	const { dryRun = false, apply = false, providers, sources, groupBy = 'dependency' } = options

	const resolvedPath = path.resolve(targetPath)

	let manifestPaths
	const stat = fs.statSync(resolvedPath)
	if (stat.isDirectory()) {
		manifestPaths = discoverManifests(resolvedPath)
		if (manifestPaths.length === 0) {
			return { exitCode: 0, output: 'No supported manifest files found.' }
		}
	} else {
		const basename = path.basename(resolvedPath)
		if (!getManifestType(basename)) {
			throw new Error(`Unsupported manifest type: ${basename}`)
		}
		manifestPaths = [resolvedPath]
	}

	const opts = {}
	if (providers) {
		opts.TRUSTIFY_DA_PROVIDERS = providers
	}
	if (sources) {
		opts.TRUSTIFY_DA_SOURCES = sources
	}

	const url = resolveBackendUrl(opts)
	const allRemediations = []
	const appliedFiles = []

	for (const manifestPath of manifestPaths) {
		const basename = path.basename(manifestPath)
		const manifestType = getManifestType(basename)
		if (!manifestType) {
			continue
		}

		let provider
		try {
			provider = match(manifestPath, availableProviders, opts)
		} catch {
			continue
		}

		const analysisReport = await analysis.requestStack(provider, manifestPath, url, false, opts)
		const remediations = extractRemediations(analysisReport, {
			providerPriority: providers ? providers.split(',') : undefined,
		})

		if (remediations.length === 0) {
			continue
		}

		allRemediations.push(...remediations)

		if (apply) {
			const content = fs.readFileSync(manifestPath, 'utf-8')
			const versionChanges = remediations.map(r => ({
				groupId: r.groupId,
				artifactId: r.artifactId,
				newVersion: r.fixedInVersion,
			}))

			const result = manifestType.updater(content, versionChanges)
			if (result.applied.length > 0) {
				fs.writeFileSync(manifestPath, result.content, 'utf-8')
				appliedFiles.push(manifestPath)
			}
		}
	}

	if (allRemediations.length === 0) {
		return { exitCode: 0, output: 'No remediations found.' }
	}

	const report = generateReport(allRemediations, { groupBy, dryRun })

	if (dryRun) {
		return { exitCode: 2, output: report }
	}

	if (apply) {
		const summary = appliedFiles.length > 0
			? `Updated ${appliedFiles.length} file(s):\n${appliedFiles.map(f => `  ${f}`).join('\n')}\n\n${report}`
			: report
		return { exitCode: 0, output: summary }
	}

	return { exitCode: 0, output: report }
}
