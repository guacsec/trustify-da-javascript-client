/**
 * Resolves the project license from the manifest and from a LICENSE / LICENSE.md file.
 * Used to report manifest-vs-file mismatch and as the baseline for dependency license compatibility.
 */

import fs from 'node:fs';
import path from 'node:path';

import { selectTrustifyDABackend } from '../index.js';
import { matchForLicense, availableProviders } from '../provider.js';
import { addProxyAgent, getTokenHeaders } from '../tools.js';

import {
	normalizeSpdx,
	readLicenseFile
} from './license_utils.js';

/**
 * Resolve project license from manifest and from LICENSE / LICENSE.md in manifest dir or git root.
 * Uses local pattern matching for LICENSE file identification (synchronous).
 * For more accurate backend-based identification, use identifyLicense() separately.
 * @param {string} manifestPath - path to manifest
 * @returns {{ fromManifest: string|null, fromFile: string|null, mismatch: boolean }}
 */
export function getProjectLicense(manifestPath) {
	const resolved = path.resolve(manifestPath);
	const provider = matchForLicense(resolved, availableProviders);
	const fromManifest = provider.readLicenseFromManifest(resolved);
	const fromFile = readLicenseFile(resolved);
	const mismatch = Boolean(
		fromManifest && fromFile && normalizeSpdx(fromManifest) !== normalizeSpdx(fromFile)
	);
	return {
		fromManifest: fromManifest || null,
		fromFile: fromFile || null,
		mismatch
	};
}

export { findLicenseFilePath, readLicenseFile } from './license_utils.js';

/**
 * Call backend /licenses/identify endpoint to identify license from file.
 * @param {string} licenseFilePath - path to LICENSE file
 * @param {{}} [opts={}] - options (proxy, token, etc.)
 * @returns {Promise<string|null>} - SPDX identifier or null
 */
export async function identifyLicense(licenseFilePath, opts = {}) {
	try {
		const fileContent = fs.readFileSync(licenseFilePath);
		const backendUrl = selectTrustifyDABackend(opts);
		const url = new URL(`${backendUrl}/api/v5/licenses/identify`);
		const tokenHeaders = getTokenHeaders(opts);
		const fetchOptions = addProxyAgent({
			method: 'POST',
			headers: {
				'Content-Type': 'application/octet-stream',
				...tokenHeaders,
			},
			body: fileContent,
		}, opts);

		const resp = await fetch(url, fetchOptions);
		if (!resp.ok) {
			return null; // Fallback to local detection on error
		}

		const data = await resp.json();
		// Extract SPDX identifier from backend response
		return data?.license?.id || data?.spdx_id || data?.identifier || null;
	} catch {
		return null; // Fallback to local detection on error
	}
}
