import { parse as parseToml } from 'smol-toml'

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
 * @param {Array<{groupId: string, artifactId: string, newVersion: string}>} versionChanges
 * @returns {{content: string, applied: Array<{groupId: string, artifactId: string, newVersion: string, oldVersion: string}>, skipped: Array<{groupId: string, artifactId: string, newVersion: string, reason: string}>}}
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
				oldVersion
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
					oldVersion: inlineVersion
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
