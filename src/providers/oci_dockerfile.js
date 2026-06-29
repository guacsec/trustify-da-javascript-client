import fs from 'node:fs'

import { generateImageSBOM, parseImageRef } from '../oci_image/utils.js'

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
 * @param {string} manifestName the manifest file name to check
 * @returns {boolean} true if the manifest is a Dockerfile or Containerfile
 */
function isSupported(manifestName) {
	return manifestName === 'Dockerfile' || manifestName === 'Containerfile'
}

/**
 * Dockerfiles have no lock file, so validation always passes.
 * @returns {boolean} always true
 */
function validateLockFile() { return true; }

/**
 * Parse the last FROM line from a Dockerfile to extract the base image reference.
 * In multi-stage builds, the last FROM represents the final stage.
 * @param {string} manifestContent the content of the Dockerfile
 * @returns {string} the image reference from the last FROM line
 * @throws {Error} when no FROM line is found in the Dockerfile
 */
export function parseFromImage(manifestContent) {
	const lines = manifestContent.split(/\r?\n/)
	let lastFrom = null
	for (const line of lines) {
		const trimmed = line.trim()
		if (/^FROM\s+/i.test(trimmed)) {
			// Extract image ref: FROM [--platform=...] image [AS name]
			const withoutFrom = trimmed.replace(/^FROM\s+/i, '')
			// Skip optional --platform flag
			const withoutFlags = withoutFrom.replace(/^--\S+\s+/, '')
			// Take only the image part (before AS alias)
			const parts = withoutFlags.split(/\s+/)
			lastFrom = parts[0]
		}
	}
	if (!lastFrom) {
		throw new Error('No FROM line found in Dockerfile')
	}
	return lastFrom
}

/**
 * Generate an image SBOM from a Dockerfile manifest using syft.
 * @param {string} manifest path to the Dockerfile
 * @param {{}} [opts={}] optional various options to pass along the application
 * @returns {{ecosystem: string, content: string, contentType: string}}
 * @private
 */
function getImageSBOM(manifest, opts = {}) {
	const manifestContent = fs.readFileSync(manifest, 'utf-8')
	const image = parseFromImage(manifestContent)
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
 * @returns {Provided}
 */
function provideComponent(manifest, opts = {}) {
	return getImageSBOM(manifest, opts)
}

/**
 * Provide content and content type for Dockerfile stack analysis.
 * @param {string} manifest path to the Dockerfile
 * @param {{}} [opts={}] optional various options to pass along the application
 * @returns {Provided}
 */
function provideStack(manifest, opts = {}) {
	return getImageSBOM(manifest, opts)
}

/**
 * Dockerfiles contain no license information.
 * @returns {null} always null
 */
function readLicenseFromManifest() { return null; }
