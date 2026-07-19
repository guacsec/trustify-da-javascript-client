import fs from 'node:fs'

import { generateImageSBOM, parseImageRef } from '../oci_image/utils.js'

import { getArgQuery, getFromQuery, getParser } from './containerfile_parser.js'

export default { isSupported, validateLockFile, provideComponent, provideStack, readLicenseFromManifest, packageManagerName() { return 'oci' } }

/** @typedef {import('../provider').Provider} */

/** @typedef {import('../provider').Provided} Provided */

/**
 * @type {string} ecosystem identifier for OCI image packages
 * @private
 */
const ecosystem = 'oci'

/**
 * Check if the given manifest name is a Dockerfile or Containerfile.
 * Supports dot-suffixed variants such as Dockerfile.dev or Containerfile.prod.
 * @param {string} manifestName the manifest file name to check
 * @returns {boolean} true if the manifest is a Dockerfile or Containerfile
 */
function isSupported(manifestName) {
	return /^(Dockerfile|Containerfile)(\..+)?$/.test(manifestName)
}

/**
 * Dockerfiles have no lock file, so validation always passes.
 * @returns {boolean} always true
 */
function validateLockFile() { return true; }

/**
 * Check whether a syntax node contains any expansion (variable substitution) children.
 * @param {import('web-tree-sitter').SyntaxNode} node
 * @returns {boolean}
 * @private
 */
function containsExpansion(node) {
	if (node.type === 'expansion') {
		return true
	}
	for (let i = 0; i < node.childCount; i++) {
		if (containsExpansion(node.child(i))) {
			return true
		}
	}
	return false
}

/**
 * Strip surrounding single or double quotes from a string.
 * @param {string} text
 * @returns {string}
 * @private
 */
function stripQuotes(text) {
	if ((text.startsWith('"') && text.endsWith('"')) || (text.startsWith("'") && text.endsWith("'"))) {
		return text.slice(1, -1)
	}
	return text
}

/**
 * Collect ARG key-value pairs from the Dockerfile AST.
 * Only ARGs with a default value are collected (ARGs without defaults cannot be resolved statically).
 * @param {import('web-tree-sitter').Tree} tree the parsed Dockerfile tree
 * @param {import('web-tree-sitter').Query} argQuery the tree-sitter query for arg_instruction nodes
 * @returns {Map<string, string>} map of ARG names to their default values
 * @private
 */
function collectArgs(tree, argQuery) {
	const args = new Map()
	for (const match of argQuery.matches(tree.rootNode)) {
		const name = match.captures.find(c => c.name === 'name')?.node.text
		const defaultValue = match.captures.find(c => c.name === 'default')?.node.text
		if (name && defaultValue) {
			args.set(name, stripQuotes(defaultValue))
		}
	}
	return args
}

/**
 * Resolve ARG substitutions in an image spec text using the collected ARG map.
 * Replaces ${VAR} and $VAR patterns with their ARG default values.
 * @param {string} text the image spec text potentially containing variable references
 * @param {Map<string, string>} args map of ARG names to their default values
 * @returns {string|null} the resolved text, or null if any variable could not be resolved
 * @private
 */
function resolveArgs(text, args) {
	let resolved = text
	let hasUnresolved = false
	resolved = resolved.replace(/\$\{([^}]+)\}|\$([A-Za-z_]\w*)/g, (_match, braced, plain) => {
		const key = braced || plain
		if (args.has(key)) {
			return args.get(key)
		}
		hasUnresolved = true
		return _match
	})
	return hasUnresolved ? null : resolved
}

/**
 * Parse all FROM instructions from a Dockerfile using tree-sitter to extract base image references.
 * In multi-stage builds, every FROM line is returned so each image can be analyzed independently.
 * ARG substitutions are resolved using declared default values. FROM lines with unresolvable
 * variables (ARGs without defaults) are silently skipped.
 * @param {string} manifestContent the content of the Dockerfile
 * @returns {Promise<string[]>} array of image references from all resolvable FROM instructions
 * @throws {Error} when no FROM instruction is found or when no FROM lines can be resolved
 */
export async function parseAllFromImages(manifestContent) {
	const [parser, fromQuery, argQuery] = await Promise.all([getParser(), getFromQuery(), getArgQuery()])
	const tree = parser.parse(manifestContent)
	const matches = fromQuery.matches(tree.rootNode)
	if (matches.length === 0) {
		throw new Error('No FROM line found in Dockerfile')
	}
	const args = collectArgs(tree, argQuery)
	const images = []
	for (const match of matches) {
		const imageSpec = match.captures.find(c => c.name === 'image').node
		if (containsExpansion(imageSpec)) {
			const resolved = resolveArgs(imageSpec.text, args)
			if (resolved != null) {
				images.push(resolved)
			}
			continue
		}
		images.push(imageSpec.text)
	}
	if (images.length === 0) {
		throw new Error('Dockerfile uses ARG substitution in all FROM lines — cannot resolve variable references')
	}
	return images
}

/**
 * Generate image SBOMs for all FROM instructions in a Dockerfile manifest using syft.
 * Returns a batch result with a purl-to-SBOM map suitable for the batch-analysis endpoint.
 * @param {string} manifest path to the Dockerfile
 * @param {{}} [opts={}] optional various options to pass along the application
 * @returns {Promise<{ecosystem: string, content: string, contentType: string, batch: boolean}>}
 * @private
 */
async function getImageSBOM(manifest, opts = {}) {
	const manifestContent = fs.readFileSync(manifest, 'utf-8')
	const images = await parseAllFromImages(manifestContent)
	const sbomByPurl = {}
	for (const image of images) {
		const imageRef = parseImageRef(image, opts)
		const purl = imageRef.getPackageURL().toString()
		if (purl in sbomByPurl) continue
		sbomByPurl[purl] = generateImageSBOM(imageRef, opts)
	}
	return {
		ecosystem,
		content: JSON.stringify(sbomByPurl),
		contentType: 'application/vnd.cyclonedx+json',
		batch: true
	}
}

/**
 * Provide content and content type for Dockerfile component analysis.
 * @param {string} manifest path to the Dockerfile
 * @param {{}} [opts={}] optional various options to pass along the application
 * @returns {Promise<Provided>}
 */
async function provideComponent(manifest, opts = {}) {
	return getImageSBOM(manifest, opts)
}

/**
 * Provide content and content type for Dockerfile stack analysis.
 * @param {string} manifest path to the Dockerfile
 * @param {{}} [opts={}] optional various options to pass along the application
 * @returns {Promise<Provided>}
 */
async function provideStack(manifest, opts = {}) {
	return getImageSBOM(manifest, opts)
}

/**
 * Dockerfiles contain no license information.
 * @returns {null} always null
 */
function readLicenseFromManifest() { return null; }
