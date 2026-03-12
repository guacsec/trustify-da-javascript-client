/**
 * License utilities: file reading, SPDX detection, normalization, compatibility.
 * This module has NO dependencies on providers or backend to avoid circular dependencies.
 */

import fs from 'node:fs';
import path from 'node:path';

const LICENSE_FILES = ['LICENSE', 'LICENSE.md', 'LICENSE.txt'];

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
 * Very simple SPDX detection from common license text (first ~500 chars).
 * @param {string} text
 * @returns {string|null}
 */
export function detectSpdxFromText(text) {
	const head = text.slice(0, 500);
	if (/Apache License,?\s*Version 2\.0/i.test(head)) { return 'Apache-2.0'; }
	if (/MIT License/i.test(head) && /Permission is hereby granted/i.test(head)) { return 'MIT'; }
	if (/GNU AFFERO GENERAL PUBLIC LICENSE\s+Version 3/i.test(head)) { return 'AGPL-3.0-only'; }
	if (/GNU LESSER GENERAL PUBLIC LICENSE\s+Version 3/i.test(head)) { return 'LGPL-3.0-only'; }
	if (/GNU LESSER GENERAL PUBLIC LICENSE\s+Version 2\.1/i.test(head)) { return 'LGPL-2.1-only'; }
	if (/GNU GENERAL PUBLIC LICENSE\s+Version 2/i.test(head)) { return 'GPL-2.0-only'; }
	if (/GNU GENERAL PUBLIC LICENSE\s+Version 3/i.test(head)) { return 'GPL-3.0-only'; }
	if (/BSD 2-Clause/i.test(head)) { return 'BSD-2-Clause'; }
	if (/BSD 3-Clause/i.test(head)) { return 'BSD-3-Clause'; }
	return null;
}

/**
 * Read LICENSE file and detect SPDX identifier.
 * @param {string} manifestPath - path to manifest
 * @returns {string|null} - SPDX identifier from LICENSE file or null
 */
export function readLicenseFile(manifestPath) {
	const licenseFilePath = findLicenseFilePath(manifestPath);
	if (!licenseFilePath) { return null; }

	try {
		const content = fs.readFileSync(licenseFilePath, 'utf-8');
		return detectSpdxFromText(content) || content.split('\n')[0]?.trim() || null;
	} catch {
		return null;
	}
}

/**
 * Get project license from manifest or LICENSE file.
 * Returns manifestLicense if provided, otherwise tries LICENSE file.
 * @param {string|null} manifestLicense - license from manifest (or null)
 * @param {string} manifestPath - path to manifest
 * @returns {string|null} - SPDX identifier or null
 */
export function getLicense(manifestLicense, manifestPath) {
	return manifestLicense || readLicenseFile(manifestPath) || null;
}

/**
 * Normalize SPDX identifier for comparison (lowercase, strip common suffixes).
 * @param {string} spdxOrName
 * @returns {string}
 */
export function normalizeSpdx(spdxOrName) {
	const s = String(spdxOrName).trim().toLowerCase();
	if (s.endsWith(' license')) { return s.slice(0, -8); }
	return s;
}

/**
 * Check if a dependency's license is compatible with the project license based on backend categories.
 *
 * @param {string} [projectCategory] - backend category for project license: PERMISSIVE | WEAK_COPYLEFT | STRONG_COPYLEFT | UNKNOWN
 * @param {string} [dependencyCategory] - backend category for dependency license: PERMISSIVE | WEAK_COPYLEFT | STRONG_COPYLEFT | UNKNOWN
 * @returns {'compatible'|'incompatible'|'unknown'}
 */
export function getCompatibility(projectCategory, dependencyCategory) {
	if (!projectCategory || !dependencyCategory) {
		return 'unknown';
	}

	const proj = projectCategory.toUpperCase();
	const dep = dependencyCategory.toUpperCase();

	if (proj === 'UNKNOWN' || dep === 'UNKNOWN') {
		return 'unknown';
	}

	const restrictiveness = {
		'PERMISSIVE': 1,
		'WEAK_COPYLEFT': 2,
		'STRONG_COPYLEFT': 3
	};

	const projLevel = restrictiveness[proj];
	const depLevel = restrictiveness[dep];

	if (projLevel === undefined || depLevel === undefined) {
		return 'unknown';
	}

	if (depLevel > projLevel) {
		return 'incompatible';
	}

	return 'compatible';
}
