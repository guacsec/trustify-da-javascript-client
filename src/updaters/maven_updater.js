import { XMLParser } from 'fast-xml-parser';

/**
 * Extracts the trimmed text content of a simple XML element from a string block.
 * @param {string} block - the XML text to search within
 * @param {string} tagName - the element name whose content to extract
 * @returns {string|null} the trimmed text content, or null if not found
 */
function extractTagContent(block, tagName) {
	const openTag = `<${tagName}>`;
	const closeTag = `</${tagName}>`;
	const start = block.indexOf(openTag);
	if (start === -1) {
		return null;
	}
	const contentStart = start + openTag.length;
	const end = block.indexOf(closeTag, contentStart);
	if (end === -1) {
		return null;
	}
	return block.substring(contentStart, end).trim();
}

/**
 * Finds the character positions of an XML element's text content within the raw file.
 * Returns the start (inclusive) and end (exclusive) offsets of the text between the
 * opening and closing tags.
 * @param {string} content - full raw XML content
 * @param {number} searchStart - start offset to search from
 * @param {number} searchEnd - end offset to search within
 * @param {string} tagName - the element name whose content position to locate
 * @returns {{start: number, end: number}|null} character offsets, or null if not found
 */
function findTagContentPosition(content, searchStart, searchEnd, tagName) {
	const openTag = `<${tagName}>`;
	const closeTag = `</${tagName}>`;

	const tagStart = content.indexOf(openTag, searchStart);
	if (tagStart === -1 || tagStart >= searchEnd) {
		return null;
	}

	const contentStart = tagStart + openTag.length;
	const tagEnd = content.indexOf(closeTag, contentStart);
	if (tagEnd === -1 || tagEnd > searchEnd) {
		return null;
	}

	return { start: contentStart, end: tagEnd };
}

/**
 * Checks whether the character immediately following a tag prefix indicates
 * that the prefix is the complete tag name (e.g. `<dependency>` vs `<dependencyManagement>`).
 * @param {string} char - the character after the tag prefix
 * @returns {boolean} true if the character terminates the tag name
 */
function isTagBoundary(char) {
	return char === '>' || char === ' ' || char === '\t'
		|| char === '\n' || char === '\r' || char === '/';
}

/**
 * Finds the text content position of a `<version>` element within the first
 * `<dependency>` block matching the given groupId and artifactId.
 * Searches through all `<dependency>` elements in the file, covering both
 * `<dependencies>` and `<dependencyManagement>` sections.
 * @param {string} content - full raw pom.xml content
 * @param {string} groupId - the dependency's groupId to match
 * @param {string} artifactId - the dependency's artifactId to match
 * @returns {{start: number, end: number}|null} version content offsets, or null
 */
function findDependencyVersionPosition(content, groupId, artifactId) {
	let searchStart = 0;
	const TAG_PREFIX = '<dependency';
	const CLOSE_TAG = '</dependency>';

	while (searchStart < content.length) {
		const start = content.indexOf(TAG_PREFIX, searchStart);
		if (start === -1) {
			break;
		}

		// Verify this is exactly <dependency> and not <dependencyManagement> etc.
		const charAfterTag = content.charAt(start + TAG_PREFIX.length);
		if (!isTagBoundary(charAfterTag)) {
			searchStart = start + 1;
			continue;
		}

		// Find closing </dependency>
		const end = content.indexOf(CLOSE_TAG, start + TAG_PREFIX.length);
		if (end === -1) {
			break;
		}

		const blockEnd = end + CLOSE_TAG.length;
		const block = content.substring(start, blockEnd);

		const gid = extractTagContent(block, 'groupId');
		const aid = extractTagContent(block, 'artifactId');

		if (gid === groupId && aid === artifactId) {
			const pos = findTagContentPosition(content, start, blockEnd, 'version');
			if (pos) {
				return pos;
			}
			// Matching dependency but no <version> element; continue searching
			// (the version may be in <dependencyManagement>)
		}

		searchStart = blockEnd;
	}
	return null;
}

/**
 * Finds the text content position of a property element inside a `<properties>` block.
 * Searches through all `<properties>` blocks in the file.
 * @param {string} content - full raw pom.xml content
 * @param {string} propName - the property element name to locate
 * @returns {{start: number, end: number}|null} property value offsets, or null
 */
function findPropertyPosition(content, propName) {
	let searchStart = 0;
	const TAG_PREFIX = '<properties';
	const CLOSE_TAG = '</properties>';

	while (searchStart < content.length) {
		const propsStart = content.indexOf(TAG_PREFIX, searchStart);
		if (propsStart === -1) {
			break;
		}

		// Verify this is exactly <properties> and not some other tag
		const charAfter = content.charAt(propsStart + TAG_PREFIX.length);
		if (!isTagBoundary(charAfter)) {
			searchStart = propsStart + 1;
			continue;
		}

		const propsCloseStart = content.indexOf(CLOSE_TAG, propsStart);
		if (propsCloseStart === -1) {
			break;
		}

		const propsBlockEnd = propsCloseStart + CLOSE_TAG.length;
		const result = findTagContentPosition(
			content, propsStart, propsBlockEnd, propName
		);
		if (result) {
			return result;
		}

		searchStart = propsBlockEnd;
	}
	return null;
}

/**
 * Resolves a Maven property chain, following `${propName}` references through
 * the properties map until a concrete (non-reference) value is reached.
 * Detects circular references via a visited set.
 * @param {string} propName - the initial property name to resolve
 * @param {Object} properties - properties map from the parsed XML
 * @param {Set<string>} [visited] - visited property names (for cycle detection)
 * @returns {{terminalPropName: string, resolvedValue: string}|{error: string}}
 */
function resolvePropertyChain(propName, properties, visited = new Set()) {
	if (visited.has(propName)) {
		const chain = [...visited, propName].join(' -> ');
		return { error: `Circular property reference detected: ${chain}` };
	}
	visited.add(propName);

	const value = properties[propName];
	if (value == null) {
		return { error: `Property '${propName}' not found in <properties>` };
	}

	const valueStr = String(value);
	const propMatch = valueStr.match(/^\$\{(.+)\}$/);
	if (propMatch) {
		return resolvePropertyChain(propMatch[1], properties, visited);
	}

	return { terminalPropName: propName, resolvedValue: valueStr };
}

/**
 * Updates dependency versions in a Maven pom.xml while preserving file formatting.
 *
 * Uses `fast-xml-parser` to understand the XML structure (dependencies and properties),
 * then performs position-based string splice to replace version strings without altering
 * any other formatting, comments, whitespace, or indentation.
 *
 * Supports `${property}` indirection: when a dependency's `<version>` is a property
 * reference, the updater resolves the property chain (including recursive references)
 * and updates the terminal property value in `<properties>` instead.
 *
 * @param {string} pomContent - the raw pom.xml file content
 * @param {Array<{groupId: string, artifactId: string, newVersion: string}>} versionChanges -
 *   list of version changes to apply
 * @returns {{content: string, applied: Array, skipped: Array}} the updated content and
 *   lists of applied and skipped changes
 */
export function updateMavenVersions(pomContent, versionChanges) {
	if (!versionChanges || versionChanges.length === 0) {
		return { content: pomContent, applied: [], skipped: [] };
	}

	const parser = new XMLParser({
		parseTagValue: false,
		commentPropName: '#comment',
	});

	let parsed;
	try {
		parsed = parser.parse(pomContent);
	} catch (e) {
		return {
			content: pomContent,
			applied: [],
			skipped: versionChanges.map(vc => ({
				groupId: vc.groupId,
				artifactId: vc.artifactId,
				newVersion: vc.newVersion,
				reason: `Failed to parse pom.xml: ${e.message}`,
			})),
		};
	}

	const project = parsed?.project;
	if (!project) {
		return {
			content: pomContent,
			applied: [],
			skipped: versionChanges.map(vc => ({
				groupId: vc.groupId,
				artifactId: vc.artifactId,
				newVersion: vc.newVersion,
				reason: 'No <project> element found in pom.xml',
			})),
		};
	}

	const properties = project.properties || {};

	const applied = [];
	const skipped = [];
	/** @type {Map<number, {start: number, end: number, newValue: string}>} */
	const replacementsByPosition = new Map();

	for (const change of versionChanges) {
		const versionPos = findDependencyVersionPosition(
			pomContent, change.groupId, change.artifactId
		);
		if (!versionPos) {
			skipped.push({
				groupId: change.groupId,
				artifactId: change.artifactId,
				newVersion: change.newVersion,
				reason: 'Dependency not found in pom.xml or has no <version> element',
			});
			continue;
		}

		const currentVersion = pomContent.substring(versionPos.start, versionPos.end);
		const propMatch = currentVersion.match(/^\$\{(.+)\}$/);

		if (propMatch) {
			const resolved = resolvePropertyChain(propMatch[1], properties);
			if (resolved.error) {
				skipped.push({
					groupId: change.groupId,
					artifactId: change.artifactId,
					newVersion: change.newVersion,
					reason: resolved.error,
				});
				continue;
			}

			const propPos = findPropertyPosition(pomContent, resolved.terminalPropName);
			if (!propPos) {
				skipped.push({
					groupId: change.groupId,
					artifactId: change.artifactId,
					newVersion: change.newVersion,
					reason: `Could not locate property '${resolved.terminalPropName}' in pom.xml`,
				});
				continue;
			}

			// Deduplicate: multiple deps may share the same property
			const existing = replacementsByPosition.get(propPos.start);
			if (existing) {
				if (existing.newValue !== change.newVersion) {
					skipped.push({
						groupId: change.groupId,
						artifactId: change.artifactId,
						newVersion: change.newVersion,
						reason: `Property '${resolved.terminalPropName}' already targeted `
							+ `with a different version '${existing.newValue}'`,
					});
					continue;
				}
				// Same replacement already queued; record as applied without duplicating
			} else {
				replacementsByPosition.set(propPos.start, {
					start: propPos.start,
					end: propPos.end,
					newValue: change.newVersion,
				});
			}

			applied.push({
				groupId: change.groupId,
				artifactId: change.artifactId,
				newVersion: change.newVersion,
				type: 'property',
				property: resolved.terminalPropName,
			});
		} else {
			const existing = replacementsByPosition.get(versionPos.start);
			if (existing) {
				if (existing.newValue !== change.newVersion) {
					skipped.push({
						groupId: change.groupId,
						artifactId: change.artifactId,
						newVersion: change.newVersion,
						reason: `Version already targeted with a different version '${existing.newValue}'`,
					});
					continue;
				}
			} else {
				replacementsByPosition.set(versionPos.start, {
					start: versionPos.start,
					end: versionPos.end,
					newValue: change.newVersion,
				});
			}

			applied.push({
				groupId: change.groupId,
				artifactId: change.artifactId,
				newVersion: change.newVersion,
				type: 'direct',
			});
		}
	}

	// Sort replacements by position descending to preserve offsets during splice
	const sortedReplacements = [...replacementsByPosition.values()]
		.sort((a, b) => b.start - a.start);

	let result = pomContent;
	for (const r of sortedReplacements) {
		result = result.substring(0, r.start) + r.newValue + result.substring(r.end);
	}

	return { content: result, applied, skipped };
}
