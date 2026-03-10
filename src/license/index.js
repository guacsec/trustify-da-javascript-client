/**
 * License resolution and dependency license compatibility for component analysis.
 */

import { getProjectLicense, findLicenseFilePath, identifyLicense } from './project_license.js';
import { licensesFromReport, getLicenseDetails } from './licenses_api.js';
import { getCompatibility } from './compatibility.js';

export { getProjectLicense, findLicenseFilePath, identifyLicense as identifyLicenseViaBackend } from './project_license.js';
export { licensesFromReport, normalizeLicensesResponse, getLicenseDetails } from './licenses_api.js';
export { getCompatibility } from './compatibility.js';

/**
 * Run full license check: resolve project license (with backend identification and details),
 * get dependency licenses from analysis report, and compute incompatibilities.
 *
 * @param {string} sbomContent - CycloneDX SBOM JSON string (the one sent for component analysis)
 * @param {string} manifestPath - path to manifest
 * @param {string} url - the backend url to send the request to
 * @param {import('../index.js').Options} [opts={}]
 * @param {import('@trustify-da/trustify-da-api-model/model/v5/AnalysisReport').AnalysisReport} [analysisResult] - analysis result that includes licenses array from backend
 * @returns {Promise<{ projectLicense: { manifest: Object|null, file: Object|null, mismatch: boolean }, incompatibleDependencies: Array<{ purl: string, licenses: string[], category?: string, reason: string }>, error?: string }>}
 */
export async function runLicenseCheck(sbomContent, manifestPath, url, opts = {}, analysisResult = null) {
	// Resolve project license from manifest and LICENSE file
	const projectLicense = getProjectLicense(manifestPath, opts);

	// Try backend identification for LICENSE file (more accurate than local pattern matching)
	const licenseFilePath = findLicenseFilePath(manifestPath);
	let backendFileId = null;
	if (licenseFilePath) {
		try {
			backendFileId = await identifyLicense(licenseFilePath, { ...opts, TRUSTIFY_DA_BACKEND_URL: url });
		} catch {
			// Fall back to local detection
		}
	}

	// Determine final license identifiers
	const manifestSpdx = projectLicense.fromManifest;
	const fileSpdx = backendFileId || projectLicense.fromFile;
	const mismatch = Boolean(manifestSpdx && fileSpdx && manifestSpdx.toLowerCase() !== fileSpdx.toLowerCase());

	// Fetch detailed license info from backend (avoid duplicate calls if same license)
	const licenseDetailsCache = new Map();

	async function getDetails(spdxId) {
		if (!spdxId || !url) return null;
		if (licenseDetailsCache.has(spdxId)) return licenseDetailsCache.get(spdxId);

		try {
			const details = await getLicenseDetails(spdxId, { ...opts, TRUSTIFY_DA_BACKEND_URL: url });
			licenseDetailsCache.set(spdxId, details);
			return details;
		} catch {
			return null;
		}
	}

	const manifestLicenseInfo = await getDetails(manifestSpdx);
	const fileLicenseInfo = await getDetails(fileSpdx);

	// Extract dependency purls from SBOM (exclude root component)
	const sbomObj = typeof sbomContent === 'string' ? JSON.parse(sbomContent) : sbomContent;
	const rootRef = sbomObj?.metadata?.component?.["bom-ref"] || sbomObj?.metadata?.component?.purl;
	const purls = (sbomObj?.components || [])
		.map(c => c.purl || c["bom-ref"])
		.filter(Boolean)
		.filter(purl => !rootRef || purl !== rootRef);

	if (purls.length === 0) {
		return {
			projectLicense: { manifest: manifestLicenseInfo, file: fileLicenseInfo, mismatch },
			incompatibleDependencies: []
		};
	}

	// Get dependency licenses from analysis report
	const licenseByPurl = licensesFromReport(analysisResult, purls);
	if (licenseByPurl.size === 0 && analysisResult) {
		return {
			projectLicense: { manifest: manifestLicenseInfo, file: fileLicenseInfo, mismatch },
			incompatibleDependencies: [],
			error: 'No license data available in analysis report'
		};
	}

	// Check compatibility for each dependency
	const projectCategory = manifestLicenseInfo?.category || fileLicenseInfo?.category;
	const incompatibleDependencies = [];

	for (const purl of purls) {
		const entry = licenseByPurl.get(purl);
		if (!entry) continue;

		const status = getCompatibility(projectCategory, entry.category);
		if (status === 'incompatible') {
			incompatibleDependencies.push({
				purl,
				licenses: entry.licenses,
				category: entry.category,
				reason: 'Dependency license(s) are incompatible with the project license.'
			});
		}
	}

	return {
		projectLicense: { manifest: manifestLicenseInfo, file: fileLicenseInfo, mismatch },
		incompatibleDependencies
	};
}
