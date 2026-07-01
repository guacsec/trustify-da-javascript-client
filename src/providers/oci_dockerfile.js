import fs from 'node:fs'

import { generateImageSBOM, parseImageRef } from '../oci_image/utils.js'

import { getFromQuery, getParser } from './containerfile_parser.js'

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
 * Parse the last FROM instruction from a Dockerfile using tree-sitter to extract the base image reference.
 * In multi-stage builds, the last FROM represents the final stage.
 * @param {string} manifestContent the content of the Dockerfile
 * @returns {Promise<string>} the image reference from the last FROM instruction
 * @throws {Error} when no FROM instruction is found or when ARG substitution is used
 */
export async function parseFromImage(manifestContent) {
	const [parser, fromQuery] = await Promise.all([getParser(), getFromQuery()])
	const tree = parser.parse(manifestContent)
	const matches = fromQuery.matches(tree.rootNode)
	if (matches.length === 0) {
		throw new Error('No FROM line found in Dockerfile')
	}
	const lastMatch = matches[matches.length - 1]
	const imageSpec = lastMatch.captures.find(c => c.name === 'image').node
	if (containsExpansion(imageSpec)) {
		throw new Error('Dockerfile uses ARG substitution in FROM line — cannot resolve variable references')
	}
	return imageSpec.text
}

/**
 * Generate an image SBOM from a Dockerfile manifest using syft.
 * @param {string} manifest path to the Dockerfile
 * @param {{}} [opts={}] optional various options to pass along the application
 * @returns {Promise<{ecosystem: string, content: string, contentType: string}>}
 * @private
 */
async function getImageSBOM(manifest, opts = {}) {
	const manifestContent = fs.readFileSync(manifest, 'utf-8')
	const image = await parseFromImage(manifestContent)
	const imageRef = parseImageRef(image, opts)
	const sbom = generateImageSBOM(imageRef, opts)
	return {
		ecosystem,
		content: JSON.stringify(sbom),
		contentType: 'application/vnd.cyclonedx+json'
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
