import { parse as parseToml } from 'smol-toml'

/**
 * One entry in {@link updateTomlVersions}' `applied` list: a version that was changed and where.
 * `type` discriminates the edit site — `'ref'` for a `[libraries]` entry pointing at a shared
 * `[versions]` alias via `version.ref` (then `versionRef` names that alias), `'inline'` for a
 * version declared directly on the library. `alias` is the library's catalog key in both cases.
 * @typedef {{
 *   groupId: string,
 *   artifactId: string,
 *   newVersion: string,
 *   oldVersion: string,
 *   type: ('ref'|'inline'),
 *   alias: string,
 *   versionRef?: string
 * }} TomlAppliedChange
 */

/**
 * Stable edit-site key for a TOML (Gradle version catalog) change: same key => same commit/PR.
 * Deps sharing one `[versions]` alias via `version.ref` share the ref key and are inseparable.
 * @param {string} manifestPath
 * @param {TomlAppliedChange} applied
 * @returns {string}
 */
export function tomlChangeKey(manifestPath, applied) {
	return applied.type === 'ref'
		? `toml:ref:${manifestPath}:${applied.versionRef}`
		: `toml:inline:${manifestPath}:${applied.alias}`
}

/**
 * Maps every edit-site key to the canonical, version-less purls of the dependencies that
 * share it, without mutating content. Used to detect whether bumping a retained remediation
 * would also affect an excluded dep.
 * @param {string} tomlContent
 * @param {string} manifestPath
 * @returns {Map<string, string[]>} editSiteKey → canonical purls
 */
export function tomlDepsForEditSite(tomlContent, manifestPath) {
	let parsed
	try {
		parsed = parseToml(tomlContent)
	} catch {
		return new Map()
	}

	const libraries = parsed.libraries || {}
	/** @type {Map<string, string[]>} */
	const siteMap = new Map()

	for (const [alias, entry] of Object.entries(libraries)) {
		const module = getModule(entry)
		if (!module) { continue }
		const [groupId, artifactId] = module.split(':')
		if (!groupId || !artifactId) { continue }

		const versionRef = getVersionRef(entry)
		const key = versionRef
			? `toml:ref:${manifestPath}:${versionRef}`
			: `toml:inline:${manifestPath}:${alias}`

		let purls = siteMap.get(key)
		if (!purls) {
			purls = []
			siteMap.set(key, purls)
		}
		purls.push(`pkg:maven/${groupId}/${artifactId}`)
	}

	return siteMap
}

/**
 * Updates dependency versions in a Gradle version catalog (libs.versions.toml) file.
 *
 * Supports two version declaration patterns:
 * - Centralized: [versions] section defines version aliases, [libraries] references via version.ref
 * - Inline: [libraries] entries include version = "x.y.z" directly
 *
 * Uses smol-toml parse() to locate keys, then performs position-based string replacement
 * on the raw content to preserve formatting and comments.
 *
 * @param {string} tomlContent - raw TOML file content
 * @param {import('../remediate.js').VersionChangeRequest[]} versionChanges
 * @returns {{content: string, applied: TomlAppliedChange[], skipped: Array<{groupId: string, artifactId: string, newVersion: string, reason: string}>}}
 */
export function updateTomlVersions(tomlContent, versionChanges) {
	const applied = []
	const skipped = []

	if (!versionChanges || versionChanges.length === 0) {
		return { content: tomlContent, applied, skipped }
	}

	let parsed
	try {
		parsed = parseToml(tomlContent)
	} catch (err) {
		for (const change of versionChanges) {
			skipped.push({
				groupId: change.groupId,
				artifactId: change.artifactId,
				newVersion: change.newVersion,
				reason: `Failed to parse TOML: ${err.message}`
			})
		}
		return { content: tomlContent, applied, skipped }
	}

	const libraries = parsed.libraries || {}
	const versions = parsed.versions || {}

	const libraryIndex = buildLibraryIndex(libraries)

	let updatedContent = tomlContent

	for (const change of versionChanges) {
		const moduleKey = `${change.groupId}:${change.artifactId}`
		const alias = libraryIndex.get(moduleKey)

		if (!alias) {
			skipped.push({
				groupId: change.groupId,
				artifactId: change.artifactId,
				newVersion: change.newVersion,
				reason: `No library entry found for module ${moduleKey}`
			})
			continue
		}

		const libEntry = libraries[alias]
		const versionRef = getVersionRef(libEntry)

		if (versionRef) {
			const oldVersion = versions[versionRef]
			if (oldVersion === undefined) {
				skipped.push({
					groupId: change.groupId,
					artifactId: change.artifactId,
					newVersion: change.newVersion,
					reason: `Version ref "${versionRef}" not found in [versions] section`
				})
				continue
			}
			if (oldVersion === change.newVersion) {
				skipped.push({
					groupId: change.groupId,
					artifactId: change.artifactId,
					newVersion: change.newVersion,
					reason: `Version already at ${change.newVersion}`
				})
				continue
			}
			updatedContent = replaceVersionInSection(
				updatedContent, versionRef, oldVersion, change.newVersion
			)
			applied.push({
				groupId: change.groupId,
				artifactId: change.artifactId,
				newVersion: change.newVersion,
				oldVersion,
				type: 'ref',
				versionRef,
				alias
			})
		} else {
			const inlineVersion = getInlineVersion(libEntry)
			if (inlineVersion === undefined) {
				skipped.push({
					groupId: change.groupId,
					artifactId: change.artifactId,
					newVersion: change.newVersion,
					reason: `No version.ref or inline version found for library "${alias}"`
				})
				continue
			}
			if (inlineVersion === change.newVersion) {
				skipped.push({
					groupId: change.groupId,
					artifactId: change.artifactId,
					newVersion: change.newVersion,
					reason: `Version already at ${change.newVersion}`
				})
				continue
			}
			const beforeInline = updatedContent
			updatedContent = replaceInlineVersion(
				updatedContent, alias, inlineVersion, change.newVersion
			)
			if (updatedContent !== beforeInline) {
				applied.push({
					groupId: change.groupId,
					artifactId: change.artifactId,
					newVersion: change.newVersion,
					oldVersion: inlineVersion,
					type: 'inline',
					alias
				})
			} else {
				skipped.push({
					groupId: change.groupId,
					artifactId: change.artifactId,
					newVersion: change.newVersion,
					reason: `Inline version replacement did not match for library "${alias}"`
				})
			}
		}
	}

	return { content: updatedContent, applied, skipped }
}

/**
 * Builds a map from "groupId:artifactId" to the TOML library alias.
 * @param {object} libraries - parsed [libraries] section
 * @returns {Map<string, string>}
 */
function buildLibraryIndex(libraries) {
	const index = new Map()
	for (const [alias, entry] of Object.entries(libraries)) {
		const module = getModule(entry)
		if (module) {
			index.set(module, alias)
		}
	}
	return index
}

/**
 * Extracts the module identifier from a library entry.
 * Handles both string shorthand ("group:artifact:version") and object notation
 * ({ module = "group:artifact" } or { group = "...", name = "..." }).
 * @param {string|object} entry
 * @returns {string|undefined} "groupId:artifactId"
 */
function getModule(entry) {
	if (typeof entry === 'string') {
		const parts = entry.split(':')
		if (parts.length >= 2) {
			return `${parts[0]}:${parts[1]}`
		}
		return undefined
	}
	if (entry.module) {
		const parts = entry.module.split(':')
		if (parts.length >= 2) {
			return `${parts[0]}:${parts[1]}`
		}
		return entry.module
	}
	if (entry.group && entry.name) {
		return `${entry.group}:${entry.name}`
	}
	return undefined
}

/**
 * Extracts the version.ref from a library entry, if present.
 * @param {string|object} entry
 * @returns {string|undefined}
 */
function getVersionRef(entry) {
	if (typeof entry === 'object' && entry.version) {
		if (typeof entry.version === 'object' && entry.version.ref) {
			return entry.version.ref
		}
	}
	return undefined
}

/**
 * Extracts an inline version string from a library entry.
 * Handles { version = "1.2.3" } and string shorthand "group:artifact:version".
 * @param {string|object} entry
 * @returns {string|undefined}
 */
function getInlineVersion(entry) {
	if (typeof entry === 'string') {
		const parts = entry.split(':')
		if (parts.length >= 3) {
			return parts[2]
		}
		return undefined
	}
	if (typeof entry === 'object' && entry.version) {
		if (typeof entry.version === 'string') {
			return entry.version
		}
	}
	return undefined
}

/**
 * Replaces a version value using position-based string replacement.
 * Targets lines matching: key = "oldVersion"
 * @param {string} content - raw TOML content
 * @param {string} key - version alias key
 * @param {string} oldVersion - current version string
 * @param {string} newVersion - replacement version string
 * @returns {string} updated content
 */
function replaceVersionInSection(content, key, oldVersion, newVersion) {
	const escapedKey = escapeRegExp(key)
	const escapedOld = escapeRegExp(oldVersion)
	const pattern = new RegExp(
		`^(\\s*${escapedKey}\\s*=\\s*")${escapedOld}("\\s*)$`,
		'm'
	)
	return content.replace(pattern, (_, p1, p2) => `${p1}${newVersion}${p2}`)
}

/**
 * Replaces an inline version in a library entry.
 * Targets patterns like: version = "oldVersion" or version ="oldVersion"
 * on the line containing the library alias.
 * @param {string} content - raw TOML content
 * @param {string} alias - library alias
 * @param {string} oldVersion - current version string
 * @param {string} newVersion - replacement version string
 * @returns {string} updated content
 */
function replaceInlineVersion(content, alias, oldVersion, newVersion) {
	const escapedAlias = escapeRegExp(alias)
	const escapedOld = escapeRegExp(oldVersion)
	const pattern = new RegExp(
		`^(\\s*${escapedAlias}\\s*=\\s*\\{[^}]*version\\s*=\\s*")${escapedOld}("[^}]*\\}\\s*)$`,
		'm'
	)
	const result = content.replace(pattern, (_, p1, p2) => `${p1}${newVersion}${p2}`)
	if (result !== content) {
		return result
	}
	const stringPattern = new RegExp(
		`^(\\s*${escapedAlias}\\s*=\\s*"[^:]+:[^:]+:)${escapedOld}("\\s*)$`,
		'm'
	)
	return content.replace(stringPattern, (_, p1, p2) => `${p1}${newVersion}${p2}`)
}

/**
 * Escapes special regex characters in a string.
 * @param {string} str
 * @returns {string}
 */
function escapeRegExp(str) {
	return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}
