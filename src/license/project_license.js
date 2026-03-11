/**
 * Resolves the project license from the manifest and from a LICENSE / LICENSE.md file.
 * Used to report manifest-vs-file mismatch and as the baseline for dependency license compatibility.
 */

import fs from 'node:fs';
import path from 'node:path';

import { selectTrustifyDABackend } from '../index.js';
import { matchForLicense, availableProviders } from '../provider.js';
import { addProxyAgent, getTokenHeaders } from '../tools.js';

const LICENSE_FILES = ['LICENSE', 'LICENSE.md', 'LICENSE.txt'];

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
	const fromFile = readLicenseFromFile(resolved);
	const mismatch = Boolean(
		fromManifest && fromFile && normalizeSpdx(fromManifest) !== normalizeSpdx(fromFile)
	);
	return {
		fromManifest: fromManifest || null,
		fromFile: fromFile || null,
		mismatch
	};
}

/**
 * Find LICENSE file path in the same directory as the manifest.
 * @param {string} manifestPath
 * @returns {string|null} - path to LICENSE file or null if not found
 */
export function findLicenseFilePath(manifestPath) {
	const manifestDir = path.dirname(path.resolve(manifestPath));

	for (const name of LICENSE_FILES) {
		const filePath = path.join(manifestDir, name);
		try {
			if (fs.statSync(filePath).isFile()) {
				return filePath;
			}
		} catch {
			// skip
		}
	}
	return null;
}

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
		const url = new URL(`${backendUrl}/licenses/identify`);
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

/**
 * Find and read LICENSE or LICENSE.md; use local pattern matching for identification.
 * @param {string} manifestPath
 * @returns {string|null}
 */
function readLicenseFromFile(manifestPath) {
	const licenseFilePath = findLicenseFilePath(manifestPath);
	if (!licenseFilePath) {return null;}

	try {
		const content = fs.readFileSync(licenseFilePath, 'utf-8');
		return detectSpdxFromText(content) || content.split('\n')[0]?.trim() || null;
	} catch {
		return null;
	}
}

/**
 * Very simple SPDX detection from common license text (first ~500 chars).
 * @param {string} text
 * @returns {string|null}
 */
function detectSpdxFromText(text) {
	const head = text.slice(0, 500);
	if (/Apache License,?\s*Version 2\.0/i.test(head)) {return 'Apache-2.0';}
	if (/MIT License/i.test(head) && /Permission is hereby granted/i.test(head)) {return 'MIT';}
	if (/GNU GENERAL PUBLIC LICENSE\s+Version 2/i.test(head)) {return 'GPL-2.0-only';}
	if (/GNU GENERAL PUBLIC LICENSE\s+Version 3/i.test(head)) {return 'GPL-3.0-only';}
	if (/BSD 2-Clause/i.test(head)) {return 'BSD-2-Clause';}
	if (/BSD 3-Clause/i.test(head)) {return 'BSD-3-Clause';}
	return null;
}

/**
 * Normalize for comparison (lowercase, strip common suffixes).
 * @param {string} spdxOrName
 * @returns {string}
 */
function normalizeSpdx(spdxOrName) {
	const s = String(spdxOrName).trim().toLowerCase();
	// e.g. "MIT" vs "MIT License"
	if (s.endsWith(' license')) {return s.slice(0, -8);}
	return s;
}
