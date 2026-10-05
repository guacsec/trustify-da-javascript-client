import fs from 'node:fs'
import path from 'node:path'

import micromatch from 'micromatch'
import { PackageURL } from 'packageurl-js'

import analysis from './analysis.js'
import { availableProviders, match } from './provider.js'
import { extractRemediations } from './remediation.js'
import { mavenChangeKey, updateMavenVersions } from './updaters/maven_updater.js'
import { tomlChangeKey, updateTomlVersions } from './updaters/toml_updater.js'

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
 *   changeKey: (manifestPath: string, applied: AppliedChange) => string
 * }} ManifestType
 */

/**
 * An isolated, single-dependency edit to one manifest file.
 * - `after` is the *original* manifest content with only this dependency's fix applied, so a caller
 *   can create an isolated commit by writing `after` to `path` on a branch cut from the base.
 * - `changeKey` is a stable identifier for the underlying edit site. Two remediations that share a
 *   `changeKey` are inseparable (e.g. two Maven deps whose versions resolve to the same `${property}`,
 *   or two Gradle libraries sharing one `version.ref`) and MUST land in the same commit/PR — the
 *   caller should union their CVEs/advisories.
 * @typedef {{ path: string, after: string, changeKey: string }} DependencyFix
 */

/**
 * A remediation grounded in the scanned workspace: the canonical
 * {@link import('./remediation.js').Remediation} base as produced by `extractRemediations`, enriched
 * by `runRemediation` with the originating manifest path(s) in `files` (always present) and,
 * optionally, the isolated per-dependency edits in `changes`.
 * @typedef {import('./remediation.js').Remediation & {
 *   files: string[],
 *   changes?: DependencyFix[]
 * }} AppliedRemediation
 */

/** @type {ManifestType[]} */
const MANIFEST_TYPES = [
	{
		test: (basename) => basename === 'pom.xml',
		updater: updateMavenVersions,
		label: 'maven',
		changeKey: mavenChangeKey
	},
	{
		test: (basename) => basename.endsWith('.versions.toml') || basename === 'libs.versions.toml',
		updater: updateTomlVersions,
		label: 'toml',
		changeKey: tomlChangeKey
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
function normalizeExcludePattern(pattern) {
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
function compileExcludeMatcher(pattern) {
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
 * Options accepted by {@link runRemediation}. See the per-field docs on the function for details.
 * @typedef {{
 *   dryRun?: boolean,
 *   providers?: string,
 *   sources?: string,
 *   backendUrl?: string,
 *   perDependencyChanges?: boolean,
 *   exclude?: string[]
 * }} RunRemediationOptions
 */

/**
 * Orchestrates the full remediation pipeline for a single manifest or directory:
 * discover manifests → scan via DA backend → extract remediations → apply or preview.
 *
 * @param {string} targetPath - path to a manifest file or directory
 * @param {RunRemediationOptions} [options]
 * @param {boolean} [options.dryRun=false] - preview changes without modifying files (applies by default)
 * @param {string} [options.providers] - comma-separated provider list
 * @param {string} [options.sources] - comma-separated source list
 * @param {string} [options.backendUrl] - Trustify DA backend URL
 * @param {boolean} [options.perDependencyChanges=false] - when true, each remediation is populated with
 *   a `changes` array describing the isolated, single-dependency edit (see {@link DependencyFix}). This lets
 *   callers create one commit/PR per dependency without attributing diff hunks themselves.
 * @param {string[]} [options.exclude=[]] - version-less purl glob patterns, e.g. `pkg:maven/com.example/legacy-lib`
 *   or `pkg:maven/com.example/*` to exclude a group. Matched with micromatch, so standard glob semantics apply:
 *   `*` matches within a `/`-segment and `**` crosses segments (`pkg:maven/**` excludes the whole ecosystem).
 *   Matching is against each remediation's canonical, version-less purl: the purl `type` is compared
 *   case-insensitively and components are percent-decoded, so `pkg:npm/@scope/*` and `pkg:npm/%40scope/*` both
 *   match `pkg:npm/@scope/x`. Matching remediations are filtered out before being applied or returned. Wired
 *   from `.trustify-da.yml`'s `remediation.exclude` via the CLI `--exclude` flag.
 * @returns {Promise<{exitCode: number, remediations: AppliedRemediation[], manifests: string[], appliedFiles: string[]}>}
 *   exitCode is 2 for a dry-run that found remediations (nothing written), 0 otherwise. `remediations`
 *   is the structured, per-manifest list of applicable updates — each entry carries the originating
 *   manifest path(s) in `files` so callers can group and create per-dependency changes. `appliedFiles`
 *   lists only the manifests actually written to disk (empty on a dry-run), so callers can report a
 *   truthful "updated N files" count without conflating "had remediations" with "was written".
 */
export async function runRemediation(targetPath, options = {}) {
	const { dryRun = false, providers, sources, perDependencyChanges = false, backendUrl, exclude = [] } = options

	// Compile exclude patterns once up front; each becomes a predicate over a dependency's
	// canonical, version-less purl (see canonicalDepPurl / compileExcludeMatcher).
	const excludeMatchers = exclude.map(compileExcludeMatcher)

	const manifestPaths = findManifests(targetPath)
	if (manifestPaths.length === 0) {
		return { exitCode: 0, remediations: [], manifests: manifestPaths, appliedFiles: [] }
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
		const extracted = extractRemediations(analysisReport, {
			providerPriority: providers ? providers.split(',').map(p => p.trim()).filter(Boolean) : undefined,
		})

		// Drop remediations whose dependency purl matches an exclude pattern, so callers
		// (and .trustify-da.yml via the CLI) can opt specific dependencies — or whole
		// groups via `*` wildcards — out of remediation entirely.
		const remediations = excludeMatchers.length === 0
			? extracted
			: extracted.filter(r => {
				const canonical = canonicalDepPurl(r.purl)
				return !excludeMatchers.some(matches => matches(canonical))
			})

		if (remediations.length === 0) {
			continue
		}

		// Tag each remediation with the manifest it came from so callers can group
		// changes per dependency across a multi-manifest workspace.
		for (const remediation of /** @type {AppliedRemediation[]} */ (remediations)) {
			remediation.files = [manifestPath]
		}

		// Read the pristine manifest once. Both the atomic apply and the per-dependency
		// change computation must diff against the *original* content.
		const needsContent = perDependencyChanges || !dryRun
		const originalContent = needsContent ? fs.readFileSync(manifestPath, 'utf-8') : null

		if (perDependencyChanges) {
			// With per-dependency changes every returned remediation must carry an isolated
			// edit. A dependency the updater cannot locate in this manifest — e.g. a vulnerable
			// *transitive* dependency surfaced by analysis but not declared here — yields no
			// applied change, so it is dropped rather than returned with an absent `changes`
			// array (which would crash callers that iterate `remediation.changes` to build PRs).
			const applicable = []
			for (const remediation of remediations) {
				const isolated = manifestType.updater(originalContent, [{
					groupId: remediation.groupId,
					artifactId: remediation.artifactId,
					newVersion: remediation.fixedInVersion,
				}])
				if (isolated.applied.length === 0) {
					continue
				}
				remediation.changes = [{
					path: manifestPath,
					after: isolated.content,
					changeKey: manifestType.changeKey(manifestPath, isolated.applied[0])
				}]
				applicable.push(remediation)
			}
			allRemediations.push(...applicable)
		} else {
			allRemediations.push(...remediations)
		}

		if (!dryRun) {
			// Disk receives the union of every dependency's fix. When
			// perDependencyChanges is also set, each remediation's `changes[].after`
			// deliberately stays isolated (single-dep) for branch-per-dep workflows.
			const result = manifestType.updater(originalContent, remediations.map(r => ({
				groupId: r.groupId,
				artifactId: r.artifactId,
				newVersion: r.fixedInVersion,
			})))
			if (result.applied.length > 0) {
				fs.writeFileSync(manifestPath, result.content, 'utf-8')
				appliedFiles.push(manifestPath)
			}
		}
	}

	if (allRemediations.length === 0) {
		return { exitCode: 0, remediations: [], manifests: manifestPaths, appliedFiles }
	}

	// Dry-run signals "changes available but not written" via exit code 2.
	return { exitCode: dryRun ? 2 : 0, remediations: allRemediations, manifests: manifestPaths, appliedFiles }
}
