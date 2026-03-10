/**
 * License compatibility: whether a dependency license is compatible with the project license.
 * Relies on backend-provided license categories.
 *
 * Compatibility is based on restrictiveness hierarchy:
 * PERMISSIVE < WEAK_COPYLEFT < STRONG_COPYLEFT
 *
 * A dependency is compatible if it's equal or less restrictive than the project license.
 * A dependency is incompatible if it's more restrictive than the project license.
 */

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

	// Unknown categories
	if (proj === 'UNKNOWN' || dep === 'UNKNOWN') {
		return 'unknown';
	}

	// Define restrictiveness levels (higher number = more restrictive)
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

	// Dependency is more restrictive than project → incompatible
	if (depLevel > projLevel) {
		return 'incompatible';
	}

	// Dependency is equal or less restrictive → compatible
	return 'compatible';
}
