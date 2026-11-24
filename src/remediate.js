import fs from 'node:fs'
import path from 'node:path'

import micromatch from 'micromatch'
import { PackageURL } from 'packageurl-js'

import analysis from './analysis.js'
import { availableProviders, match } from './provider.js'
import { discoverGradleSubprojects, findNearestBuildFile } from './providers/java_gradle.js'
import { extractRemediations, compareVersions } from './remediation.js'
import { mavenChangeKey, mavenDepsForEditSite, updateMavenVersions } from './updaters/maven_updater.js'
import { tomlChangeKey, tomlDepsForEditSite, updateTomlVersions } from './updaters/toml_updater.js'

import { selectTrustifyDABackend } from './index.js'

// Mirrors DEFAULT_WORKSPACE_DISCOVERY_IGNORE in workspace.js
const SKIP_DIRS = new Set(['node_modules', '.git'])

/**
 * A single version change requested from an updater: bump `groupId:artifactId` to `newVersion`.
 * The input side of every updater; each updater's output side (its `applied` entries) is its own
 * type — see {@link AppliedChange}.
 * @typedef {{groupId: string, artifactId: string, newVersion: string}} VersionChangeRequest
 */

/**
 * One entry from an updater's `applied` list, describing where and how a version was changed.
 * Owned by the updater layer: the union of each updater's applied-entry shape. `changeKey`
 * (per {@link ManifestType}) turns one of these into a stable edit-site identifier.
 * @typedef {import('./updaters/maven_updater.js').MavenAppliedChange
 *   | import('./updaters/toml_updater.js').TomlAppliedChange} AppliedChange
 */

/**
 * The result of running an updater over a manifest's raw content.
 * @typedef {{content: string, applied: AppliedChange[], skipped: Array<{groupId: string, artifactId: string, newVersion: string, reason: string}>}} UpdaterResult
 */

/**
 * A supported manifest type and the operations that act on it.
 * `changeKey` builds a stable edit-site key from a single `applied` entry, so callers can detect
 * inseparable remediations (same key => same commit/PR).
 * @typedef {{
 *   test: (basename: string) => boolean,
 *   updater: (content: string, versionChanges: VersionChangeRequest[]) => UpdaterResult,
 *   label: ('maven'|'toml'),
 *   changeKey: (manifestPath: string, applied: AppliedChange) => string,
 *   depsForEditSite: (content: string, manifestPath: string) => Map<string, string[]>
 * }} ManifestType
 */

/**
 * A remediation grounded in the scanned workspace: the canonical
 * {@link import('./remediation.js').Remediation} base as produced by `extractRemediations`, enriched
 * by `runRemediation` with the originating manifest path(s) in `files` (always present).
 * @typedef {import('./remediation.js').Remediation & {
 *   files: string[],
 * }} AppliedRemediation
 */

/**
 * One group of inseparable remediations sharing the same edit site (changeKey).
 * @typedef {{
 *   changeKey: string,
 *   appliedVersion: string,
 *   remediations: AppliedRemediation[],
 *   edit: { path: string, after: string },
 *   divergent: boolean,
 * }} RemediationGroup
 */

/** @type {ManifestType[]} */
const MANIFEST_TYPES = [
	{
		test: (basename) => basename === 'pom.xml',
		updater: updateMavenVersions,
		label: 'maven',
		changeKey: mavenChangeKey,
		depsForEditSite: mavenDepsForEditSite
	},
	{
		test: (basename) => basename.endsWith('.versions.toml') || basename === 'libs.versions.toml',
		updater: updateTomlVersions,
		label: 'toml',
		changeKey: tomlChangeKey,
		depsForEditSite: tomlDepsForEditSite
	},
]

/**
 * Returns the manifest type descriptor for a given filename, or null if unsupported.
 * @param {string} basename - the file name to check
 * @returns {ManifestType|null}
 */
function getManifestType(basename) {
	return MANIFEST_TYPES.find(t => t.test(basename)) || null
}

/**
 * Reduces a dependency purl to its canonical, version-less identity for exclude matching:
 * `pkg:<type>/<namespace>/<name>`, with the type lowercased (purl types are
 * case-insensitive) and all components percent-decoded by {@link PackageURL} (so an npm
 * scope compares as `@scope`, not `%40scope`). Returns the raw input unchanged if it
 * cannot be parsed, so an unparseable purl can still match an identical literal pattern.
 * @param {string} purl - a full package URL, e.g. `pkg:maven/com.example/legacy-lib@1.0.0`
 * @returns {string} the canonical version-less purl, e.g. `pkg:maven/com.example/legacy-lib`
 */
function canonicalDepPurl(purl) {
	try {
		const p = PackageURL.fromString(purl)
		const namespace = p.namespace ? `${p.namespace}/` : ''
		return `pkg:${p.type.toLowerCase()}/${namespace}${p.name}`
	} catch {
		return purl
	}
}

/**
 * Normalizes an exclude pattern to the same canonical shape as {@link canonicalDepPurl}:
 * lowercases the `pkg:<type>` segment and percent-decodes each path segment, so a pattern
 * written as `pkg:NPM/@scope/*` or `pkg:npm/%40scope/*` both match `pkg:npm/@scope/name`.
 * `*` wildcards are preserved (they are not percent-encoded).
 * @param {string} pattern
 * @returns {string}
 */
export function normalizeExcludePattern(pattern) {
	const withoutScheme = pattern.replace(/^pkg:/i, '')
	const slash = withoutScheme.indexOf('/')
	if (slash === -1) {
		return `pkg:${withoutScheme.toLowerCase()}`
	}
	const type = withoutScheme.slice(0, slash).toLowerCase()
	const rest = withoutScheme.slice(slash + 1).split('/').map(segment => {
		try {
			return decodeURIComponent(segment)
		} catch {
			return segment
		}
	}).join('/')
	return `pkg:${type}/${rest}`
}

/**
 * Compiles an exclude pattern into a predicate over canonical dep purls, delegating to
 * micromatch (the same glob engine used for workspace discovery in workspace.js). Patterns
 * share the `pkg:<type>/<namespace>/<name>` shape and use standard glob semantics: `*` matches
 * within a `/`-delimited segment (e.g. `pkg:maven/com.example/*` excludes every artifact in that
 * group) and `**` crosses segments (e.g. `pkg:maven/**` excludes the whole ecosystem). Brace
 * expansion is therefore available too. A pattern without wildcards is an exact
 * (normalized) match.
 * @param {string} pattern
 * @returns {(canonicalPurl: string) => boolean}
 */
export function compileExcludeMatcher(pattern) {
	const normalized = normalizeExcludePattern(pattern)
	return canonicalPurl => micromatch.isMatch(canonicalPurl, normalized)
}

/**
 * Resolves a target path to the supported manifest files it contains: the single file
 * if `targetPath` is a supported manifest, or every supported manifest discovered
 * recursively if it's a directory. This is the single source of truth for what
 * `runRemediation` will scan, so callers (e.g. the CLI) can reuse it to tell
 * "no manifests here" apart from "manifests, but nothing to fix".
 * @param {string} targetPath - path to a manifest file or directory
 * @returns {string[]} absolute paths to supported manifests (empty for an empty directory)
 * @throws if the path does not exist, or is a file of an unsupported manifest type
 */
export function findManifests(targetPath) {
	const resolvedPath = path.resolve(targetPath)

	let stat
	try {
		stat = fs.statSync(resolvedPath)
	} catch {
		throw new Error(`Path not found: ${resolvedPath}`)
	}

	// A single file must itself be a supported manifest.
	if (!stat.isDirectory()) {
		const basename = path.basename(resolvedPath)
		if (!getManifestType(basename)) {
			throw new Error(`Unsupported manifest type: ${basename}`)
		}
		return [resolvedPath]
	}

	// A directory yields every supported manifest found recursively beneath it.
	const manifests = []
	function walk(dir) {
		for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
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
	walk(resolvedPath)
	return manifests
}

/**
 * Resolves which manifests must be analyzed to produce remediations for `manifestPath`.
 *
 * Maven manifests are analyzed as-is. A Gradle version catalog is shared by every project
 * in its build, while `gradle dependencies` only reports the project it runs in, so the
 * catalog's owning build is expanded to all of its projects. Falls back to analyzing the
 * catalog itself when the build cannot be discovered (no settings file) or has no projects.
 *
 * @param {string} manifestPath - the manifest being remediated
 * @param {ManifestType} manifestType
 * @param {Object} opts - client options
 * @returns {Promise<string[]>} manifests to analyze
 */
async function analysisPathsFor(manifestPath, manifestType, opts) {
	if (manifestType.label !== 'toml') {
		return [manifestPath]
	}

	const buildFile = findNearestBuildFile(path.dirname(manifestPath))
	if (!buildFile) {
		return [manifestPath]
	}

	const projects = await discoverGradleSubprojects(path.dirname(buildFile), opts)
	return projects.length > 0 ? projects : [manifestPath]
}

/**
 * Resolves a version conflict among candidates. Default: highest version wins.
 * @param {string[]} versions
 * @param {((versions: string[]) => string)} [resolve]
 * @returns {string}
 */
function resolveConflict(versions, resolve) {
	if (resolve) {
		return resolve(versions)
	}
	return versions.sort((a, b) => compareVersions(b, a))[0]
}

/**
 * Options accepted by {@link runRemediation}. See the per-field docs on the function for details.
 * @typedef {{
 *   dryRun?: boolean,
 *   providers?: string,
 *   sources?: string,
 *   backendUrl?: string,
 *   conflictResolution?: (versions: string[]) => string,
 *   exclude?: string[]
 * }} RunRemediationOptions
 */

/**
 * Orchestrates the full remediation pipeline for a single manifest or directory:
 * discover manifests → scan via DA backend → extract remediations → group by edit site →
 * resolve conflicts → produce isolated and combined content → optionally write to disk.
 *
 * @param {string} targetPath - path to a manifest file or directory
 * @param {RunRemediationOptions} [options]
 * @param {boolean} [options.dryRun=false] - preview changes without modifying files (applies by default)
 * @param {string} [options.providers] - comma-separated provider list
 * @param {string} [options.sources] - comma-separated source list
 * @param {string} [options.backendUrl] - Trustify DA backend URL
 * @param {function} [options.conflictResolution] - function `(versions: string[]) => string` to resolve
 *   version conflicts within a group. Default picks the highest version.
 * @param {string[]} [options.exclude=[]] - version-less purl glob patterns, e.g. `pkg:maven/com.example/legacy-lib`
 *   or `pkg:maven/com.example/*` to exclude a group. Matched with micromatch, so standard glob semantics apply:
 *   `*` matches within a `/`-segment and `**` crosses segments (`pkg:maven/**` excludes the whole ecosystem).
 *   Matching is against each remediation's canonical, version-less purl: the purl `type` is compared
 *   case-insensitively and components are percent-decoded, so `pkg:npm/@scope/*` and `pkg:npm/%40scope/*` both
 *   match `pkg:npm/@scope/x`. Matching remediations are filtered out before being applied or returned. Wired
 *   from `.trustify-da.yml`'s `remediation.exclude` via the CLI `--exclude` flag.
 * @returns {Promise<{exitCode: number, groups: RemediationGroup[], remediations: AppliedRemediation[], manifests: string[], appliedFiles: string[], skipped: Array<{groupId: string, artifactId: string, newVersion: string, reason: string}>}>}
 *   exitCode is 2 for a dry-run that found remediations (nothing written), 0 otherwise. `groups` is the
 *   primary structure — each group represents one inseparable edit site. `remediations` is a flat convenience
 *   accessor (`groups.flatMap(g => g.remediations)`). `appliedFiles` lists only the manifests actually written
 *   to disk (empty on a dry-run).
 */
export async function runRemediation(targetPath, options = {}) {
	const { dryRun = false, providers, sources, conflictResolution, backendUrl, exclude = [] } = options

	const excludeMatchers = exclude.map(compileExcludeMatcher)

	const manifestPaths = findManifests(targetPath)
	if (manifestPaths.length === 0) {
		return { exitCode: 0, groups: [], remediations: [], manifests: manifestPaths, appliedFiles: [], skipped: [] }
	}

	const opts = {}
	if (backendUrl !== undefined) {
		opts.TRUSTIFY_DA_BACKEND_URL = backendUrl
	}
	if (providers !== undefined) {
		opts.TRUSTIFY_DA_PROVIDERS = providers
	}
	if (sources !== undefined) {
		opts.TRUSTIFY_DA_SOURCES = sources
	}

	const url = selectTrustifyDABackend(opts)
	/** @type {RemediationGroup[]} */
	const allGroups = []
	const appliedFiles = []
	/** @type {Array<{groupId: string, artifactId: string, newVersion: string, reason: string}>} */
	const allSkipped = []

	for (const manifestPath of manifestPaths) {
		const basename = path.basename(manifestPath)
		const manifestType = getManifestType(basename)
		if (!manifestType) {
			continue
		}

		const providerPriority = providers ? providers.split(',').map(p => p.trim()).filter(Boolean) : undefined
		const analysisPaths = await analysisPathsFor(manifestPath, manifestType, opts)

		// A dependency visible from several projects yields one remediation per analysis.
		// Keep a single entry per purl so it is reported and edited once.
		/** @type {Map<string, import('./remediation.js').Remediation>} */
		const remediationsByPurl = new Map()
		for (const analysisPath of analysisPaths) {
			let provider
			try {
				provider = match(analysisPath, availableProviders, opts)
			} catch {
				continue
			}

			const analysisReport = await analysis.requestStack(provider, analysisPath, url, false, opts)
			for (const remediation of extractRemediations(analysisReport, { providerPriority })) {
				if (!remediationsByPurl.has(remediation.purl)) {
					remediationsByPurl.set(remediation.purl, remediation)
				}
			}
		}
		const extracted = [...remediationsByPurl.values()].sort((a, b) => a.purl.localeCompare(b.purl))

		let remediations = excludeMatchers.length === 0
			? extracted
			: extracted.filter(r => {
				const canonical = canonicalDepPurl(r.purl)
				return !excludeMatchers.some(matches => matches(canonical))
			})

		if (remediations.length === 0) {
			continue
		}

		const originalContent = fs.readFileSync(manifestPath, 'utf-8')
		const editSiteMap = excludeMatchers.length > 0
			? manifestType.depsForEditSite(originalContent, manifestPath)
			: null

		// Single pass: discover changeKeys, check exclude co-location, and group.
		// One updater call per remediation (transitives that can't be located are dropped).
		/** @type {Map<string, AppliedRemediation[]>} */
		const groups = new Map()
		for (const remediation of /** @type {AppliedRemediation[]} */ (remediations)) {
			remediation.files = [manifestPath]
			const isolated = manifestType.updater(originalContent, [{
				groupId: remediation.groupId,
				artifactId: remediation.artifactId,
				newVersion: remediation.fixedInVersion,
			}])
			if (isolated.applied.length === 0) {
				allSkipped.push({
					groupId: remediation.groupId,
					artifactId: remediation.artifactId,
					newVersion: remediation.fixedInVersion,
					reason: manifestType.label === 'toml'
						? 'Dependency not declared in the version catalog'
						: 'Dependency not directly declared in the manifest',
				})
				continue
			}
			const key = manifestType.changeKey(manifestPath, isolated.applied[0])

			if (editSiteMap) {
				const selfPurl = canonicalDepPurl(remediation.purl)
				const coLocated = editSiteMap.get(key) || []
				const excludedPurl = coLocated.find(purl => {
					const canonical = canonicalDepPurl(purl)
					return canonical !== selfPurl && excludeMatchers.some(m => m(canonical))
				})
				if (excludedPurl) {
					const editType = manifestType.label === 'maven' ? 'Maven property' : 'Gradle version.ref'
					allSkipped.push({
						groupId: remediation.groupId,
						artifactId: remediation.artifactId,
						newVersion: remediation.fixedInVersion,
						reason: `Shares a ${editType} with excluded dependency ${canonicalDepPurl(excludedPurl)}`,
					})
					continue
				}
			}

			let group = groups.get(key)
			if (!group) {
				group = []
				groups.set(key, group)
			}
			group.push(remediation)
		}

		if (groups.size === 0) {
			continue
		}

		// Resolve conflicts and produce per-group isolated content.
		const allChanges = []
		for (const [changeKey, members] of groups) {
			const uniqueVersions = [...new Set(members.map(r => r.fixedInVersion))]
			let appliedVersion
			if (uniqueVersions.length === 1) {
				appliedVersion = uniqueVersions[0]
			} else {
				appliedVersion = resolveConflict(uniqueVersions, conflictResolution)
				if (!uniqueVersions.includes(appliedVersion)) {
					throw new Error(`conflictResolution returned '${appliedVersion}', which is not one of the candidates: ${uniqueVersions.join(', ')}`)
				}
			}

			const changes = members.map(r => ({
				groupId: r.groupId, artifactId: r.artifactId, newVersion: appliedVersion,
			}))
			const result = manifestType.updater(originalContent, changes)

			allGroups.push({
				changeKey,
				appliedVersion,
				remediations: members,
				edit: { path: manifestPath, after: result.content },
				divergent: members.some(r => r.fixedInVersion !== appliedVersion),
			})

			allChanges.push(...changes)
		}

		if (!dryRun) {
			const combined = manifestType.updater(originalContent, allChanges)
			if (combined.applied.length > 0) {
				fs.writeFileSync(manifestPath, combined.content, 'utf-8')
				appliedFiles.push(manifestPath)
			}
		}
	}

	const flatRemediations = allGroups.flatMap(g => g.remediations)

	if (flatRemediations.length === 0) {
		return { exitCode: 0, groups: [], remediations: [], manifests: manifestPaths, appliedFiles, skipped: allSkipped }
	}

	return { exitCode: dryRun ? 2 : 0, groups: allGroups, remediations: flatRemediations, manifests: manifestPaths, appliedFiles, skipped: allSkipped }
}
