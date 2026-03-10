/**
 * Resolves the project license from the manifest and from a LICENSE / LICENSE.md file.
 * Used to report manifest-vs-file mismatch and as the baseline for dependency license compatibility.
 */

import fs from 'node:fs';
import path from 'node:path';

import { XMLParser } from 'fast-xml-parser';

import { getCustom } from '../tools.js';

const LICENSE_FILES = ['LICENSE', 'LICENSE.md', 'LICENSE.txt'];

/**
 * Resolve project license from the manifest file only (no LICENSE file).
 * @param {string} manifestPath - path to manifest (e.g. package.json, pom.xml)
 * @param {{}} [opts={}] - options (for getCustom, etc.)
 * @returns {{ fromManifest: string|null, fromFile: null, mismatch: false }}
 */
export function getProjectLicenseFromManifest(manifestPath, opts = {}) {
	const fromManifest = readLicenseFromManifest(manifestPath, opts);
	return {
		fromManifest: fromManifest || null,
		fromFile: null,
		mismatch: false
	};
}

/**
 * Resolve project license from manifest and from LICENSE / LICENSE.md in manifest dir or git root.
 * Uses local pattern matching for LICENSE file identification (synchronous).
 * For more accurate backend-based identification, use identifyLicenseViaBackend() separately.
 * @param {string} manifestPath - path to manifest
 * @param {{}} [opts={}] - options
 * @returns {{ fromManifest: string|null, fromFile: string|null, mismatch: boolean }}
 */
export function getProjectLicense(manifestPath, opts = {}) {
	const fromManifest = readLicenseFromManifest(manifestPath, opts);
	const fromFile = readLicenseFromFile(manifestPath);
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
 * Read license from manifest (package.json, pom.xml). Returns null if not present or unsupported manifest.
 * @param {string} manifestPath
 * @param {{}} [opts]
 * @returns {string|null}
 */
function readLicenseFromManifest(manifestPath, opts) {
	const base = path.basename(manifestPath);
	if (base === 'package.json') {
		return readLicenseFromPackageJson(manifestPath);
	}
	if (base === 'pom.xml') {
		return readLicenseFromPomXml(manifestPath);
	}
	// build.gradle, go.mod, requirements.txt: no standard license field
	return null;
}

/**
 * @param {string} manifestPath
 * @returns {string|null}
 */
function readLicenseFromPackageJson(manifestPath) {
	try {
		const content = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
		if (typeof content.license === 'string') {
			return content.license.trim() || null;
		}
		if (Array.isArray(content.licenses) && content.licenses.length > 0) {
			const first = content.licenses[0];
			const name = first.type || first.name;
			return typeof name === 'string' ? name.trim() : null;
		}
		return null;
	} catch {
		return null;
	}
}

/**
 * @param {string} manifestPath
 * @returns {string|null}
 */
function readLicenseFromPomXml(manifestPath) {
	try {
		const xml = fs.readFileSync(manifestPath, 'utf-8');
		const parser = new XMLParser({ ignoreAttributes: false });
		const obj = parser.parse(xml);
		const project = obj?.project;
		if (!project?.licenses?.license) {
			return null;
		}
		const license = Array.isArray(project.licenses.license)
			? project.licenses.license[0]
			: project.licenses.license;
		const name = (license?.name && license.name.trim()) || null;
		if (!name) {
			return null;
		}

		return name;
	} catch {
		return null;
	}
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
 * @param {string} backendUrl - backend base URL
 * @param {{}} [opts={}] - options (proxy, token, etc.)
 * @returns {Promise<string|null>} - SPDX identifier or null
 */
export async function identifyLicenseViaBackend(licenseFilePath, backendUrl, opts = {}) {
	try {
		const fileContent = fs.readFileSync(licenseFilePath);
		const url = `${backendUrl.replace(/\/$/, '')}/licenses/identify`;
		const tokenHeaders = getTokenHeaders(opts);
		const fetchOptions = {
			method: 'POST',
			headers: {
				'Content-Type': 'application/octet-stream',
				...tokenHeaders,
			},
			body: fileContent,
		};

		const proxyUrl = getCustom('TRUSTIFY_DA_PROXY_URL', null, opts);
		if (proxyUrl) {
			const { HttpsProxyAgent } = await import('https-proxy-agent');
			fetchOptions.agent = new HttpsProxyAgent(proxyUrl);
		}

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
	if (!licenseFilePath) return null;

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
	if (/Apache License,?\s*Version 2\.0/i.test(head)) return 'Apache-2.0';
	if (/MIT License/i.test(head) && /Permission is hereby granted/i.test(head)) return 'MIT';
	if (/GNU GENERAL PUBLIC LICENSE\s+Version 2/i.test(head)) return 'GPL-2.0-only';
	if (/GNU GENERAL PUBLIC LICENSE\s+Version 3/i.test(head)) return 'GPL-3.0-only';
	if (/BSD 2-Clause/i.test(head)) return 'BSD-2-Clause';
	if (/BSD 3-Clause/i.test(head)) return 'BSD-3-Clause';
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
	if (s.endsWith(' license')) return s.slice(0, -8);
	return s;
}
