/**
 * License compatibility: whether a dependency license is compatible with the project license.
 * Uses a minimal in-client matrix; the backend may provide compatibility in the future.
 */

/**
 * Check if a dependency's license(s) are compatible with the project license.
 * When the backend provides dependencyCategory (from License Analysis API / analysis report), it is used for more accurate compatibility.
 *
 * @param {string|null} projectLicense - SPDX id or name from manifest/file
 * @param {string[]} dependencyLicenses - SPDX ids or names for the dependency
 * @param {string} [dependencyCategory] - optional category from backend: PERMISSIVE | WEAK_COPYLEFT | STRONG_COPYLEFT | UNKNOWN
 * @returns {'compatible'|'incompatible'|'unknown'}
 */
export function getCompatibility(projectLicense, dependencyLicenses, dependencyCategory) {
	if (!projectLicense) {return 'unknown';}
	if (!dependencyLicenses?.length) {return 'unknown';}

	// Use backend category when available (from API v5 licenses / analysis report)
	const cat = String(dependencyCategory || '').toUpperCase();
	if (cat === 'STRONG_COPYLEFT') {
		const proj = projectLicense ? normalize(projectLicense) : '';
		if (isPermissive(proj)) {return 'incompatible';}
		if (isCopyleft(proj)) {return 'unknown';}
		return 'incompatible';
	}
	if (cat === 'WEAK_COPYLEFT') {
		const proj = projectLicense ? normalize(projectLicense) : '';
		if (isPermissive(proj)) {return 'unknown';} // weak copyleft often acceptable when used as library
		return 'unknown';
	}
	if (cat === 'PERMISSIVE' && (!projectLicense || isPermissive(normalize(projectLicense)))) {return 'compatible';}

	if (!projectLicense || !dependencyLicenses?.length) {return 'unknown';}

	const proj = normalize(projectLicense);
	const depSet = new Set(dependencyLicenses.map(normalize).filter(Boolean));

	// Same license or both permissive -> compatible
	if (depSet.has(proj)) {return 'compatible';}
	if (isPermissive(proj) && [...depSet].every(isPermissive)) {return 'compatible';}

	// Project is permissive; dependency is copyleft -> flag for user awareness
	if (isPermissive(proj) && [...depSet].some(isCopyleft)) {return 'incompatible';}

	// Project is copyleft; dependency is different copyleft or proprietary -> unknown / depends on linking
	if (isCopyleft(proj)) {return 'unknown';}

	return 'unknown';
}

function normalize(id) {
	return String(id).trim().toLowerCase().replace(/\s+/g, '-');
}

function isPermissive(id) {
	const n = normalize(id);
	return ['mit', 'apache-2.0', 'bsd-2-clause', 'bsd-3-clause', 'isc', '0bsd'].includes(n) ||
		n.startsWith('apache-') || n.startsWith('bsd-');
}

function isCopyleft(id) {
	const n = normalize(id);
	return ['gpl-2.0-only', 'gpl-2.0-or-later', 'gpl-3.0-only', 'gpl-3.0-or-later',
		'agpl-3.0-only', 'agpl-3.0-or-later'].includes(n) || n.startsWith('gpl-') || n.startsWith('agpl-');
}
