import fs from 'node:fs'
import path from 'node:path'

import analysis from './analysis.js'
import { availableProviders, match } from './provider.js'
import { extractRemediations } from './remediation.js'
import { generateReport } from './remediation_report.js'
import { updateMavenVersions } from './updaters/maven_updater.js'
import { updateTomlVersions } from './updaters/toml_updater.js'

import { selectTrustifyDABackend } from './index.js'

// Mirrors DEFAULT_WORKSPACE_DISCOVERY_IGNORE in workspace.js
const SKIP_DIRS = new Set(['node_modules', '.git'])

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
			if (SKIP_DIRS.has(entry.name)) {
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
 * Orchestrates the full remediation pipeline for a single manifest or directory:
 * discover manifests → scan via DA backend → extract remediations → apply or preview.
 *
 * @param {string} targetPath - path to a manifest file or directory
 * @param {object} [options]
 * @param {boolean} [options.dryRun=false] - preview changes without modifying files (applies by default)
 * @param {string} [options.providers] - comma-separated provider list
 * @param {string} [options.sources] - comma-separated source list
 * @param {'dependency'|'bundle'} [options.groupBy='dependency'] - report grouping strategy
 * @returns {Promise<{exitCode: number, output: string}>}
 */
export async function runRemediation(targetPath, options = {}) {
	const { dryRun = false, providers, sources, groupBy = 'dependency' } = options

	const resolvedPath = path.resolve(targetPath)

	let manifestPaths
	let stat
	try {
		stat = fs.statSync(resolvedPath)
	} catch {
		throw new Error(`Path not found: ${resolvedPath}`)
	}
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

	const url = selectTrustifyDABackend(opts)
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
			providerPriority: providers ? providers.split(',').map(p => p.trim()).filter(Boolean) : undefined,
		})

		if (remediations.length === 0) {
			continue
		}

		allRemediations.push(...remediations)

		if (!dryRun) {
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

	const report = generateReport(allRemediations, { groupBy })

	if (dryRun) {
		return { exitCode: 2, output: report }
	}

	const summary = appliedFiles.length > 0
		? `Updated ${appliedFiles.length} file(s):\n${appliedFiles.map(f => `  ${f}`).join('\n')}\n\n${report}`
		: report
	return { exitCode: 0, output: summary }
}
