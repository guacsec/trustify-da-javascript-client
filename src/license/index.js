/**
 * License resolution and dependency license compatibility for component analysis.
 */

import { getProjectLicense, findLicenseFilePath, identifyLicense } from './project_license.js';
import { licenseMapFromAnalysisReport, getLicenseDetails } from './licenses_api.js';
import { getCompatibility } from './compatibility.js';

export { getProjectLicense, getProjectLicenseFromManifest, findLicenseFilePath, identifyLicense as identifyLicenseViaBackend } from './project_license.js';
export { licenseMapFromAnalysisReport, normalizeLicensesResponse, getLicensesByPurl, getLicenseDetails } from './licenses_api.js';
export { getCompatibility } from './compatibility.js';

/**
 * Extract all component purls from a CycloneDX SBOM JSON string (excluding root if desired).
 * @param {string} sbomContent - CycloneDX JSON string
 * @param {boolean} [excludeRoot=true] - if true, exclude the root component's purl from the list
 * @returns {string[]}
 */
export function extractPurlsFromSbom(sbomContent, excludeRoot = true) {
	let obj;
	try {
		obj = typeof sbomContent === 'string' ? JSON.parse(sbomContent) : sbomContent;
	} catch {
		return [];
	}
	const components = obj?.components;
	if (!Array.isArray(components)) return [];

	const rootRef = obj?.metadata?.component?.["bom-ref"] ?? obj?.metadata?.component?.purl;
	const purls = components
		.map(c => c.purl || c["bom-ref"] || c.bomRef)
		.filter(Boolean);

	if (excludeRoot && rootRef) {
		const rootPurl = typeof rootRef === 'string' ? rootRef : rootRef?.purl;
		return purls.filter(p => p !== rootPurl);
	}
	return purls;
}

/**
 * Run full license check: resolve project license (with backend identification and details),
 * get dependency licenses from analysis report, and compute incompatibilities.
 *
 * @param {string} sbomContent - CycloneDX SBOM JSON string (the one sent for component analysis)
 * @param {string} manifestPath - path to manifest
 * @param {string} backendUrl - Trustify DA backend base URL
 * @param {import('../index.js').Options} [opts={}]
 * @param {import('@trustify-da/trustify-da-api-model/model/v5/AnalysisReport').AnalysisReport} [analysisResult] - analysis result that includes licenses array from backend
 * @returns {Promise<{ projectLicense: { manifest: Object|null, file: Object|null, mismatch: boolean }, incompatibleDependencies: Array<{ purl: string, licenses: string[], category?: string, reason: string }>, error?: string }>}
 */
export async function runLicenseCheck(sbomContent, manifestPath, backendUrl, opts = {}, analysisResult = null) {
	// Get project license from manifest (always available)
	const projectLicense = getProjectLicense(manifestPath, opts);

	// Try to get more accurate LICENSE file identification from backend
	let projectLicenseFromFileBackend = null;
	const licenseFilePath = findLicenseFilePath(manifestPath);
	if (licenseFilePath && backendUrl) {
		try {
			projectLicenseFromFileBackend = await identifyLicense(licenseFilePath, backendUrl, opts);
		} catch {
			// Fall back to local detection (already in projectLicense.fromFile)
		}
	}

	// Use backend identification if available, otherwise use local detection
	const finalFromFile = projectLicenseFromFileBackend || projectLicense.fromFile;
	const finalMismatch = Boolean(
		projectLicense.fromManifest && finalFromFile &&
		projectLicense.fromManifest.toLowerCase() !== finalFromFile.toLowerCase()
	);

	// Fetch detailed license info from backend for both manifest and file licenses
	let manifestLicenseInfo = null;
	let fileLicenseInfo = null;

	if (projectLicense.fromManifest && backendUrl) {
		try {
			manifestLicenseInfo = await getLicenseDetails(projectLicense.fromManifest, backendUrl, opts);
		} catch {
			// Backend might not have this license; keep as null
		}
	}

	if (finalFromFile && backendUrl) {
		try {
			fileLicenseInfo = await getLicenseDetails(finalFromFile, backendUrl, opts);
		} catch {
			// Backend might not have this license; keep as null
		}
	}

	const purls = extractPurlsFromSbom(sbomContent, true);
	if (purls.length === 0) {
		return {
			projectLicense: {
				manifest: manifestLicenseInfo,
				file: fileLicenseInfo,
				mismatch: finalMismatch
			},
			incompatibleDependencies: []
		};
	}

	// Get dependency licenses from analysis report (backend already provides this)
	const licenseByPurl = licenseMapFromAnalysisReport(analysisResult, purls);
	if (licenseByPurl.size === 0 && analysisResult) {
		// No license data in analysis report - this might be expected for some backends
		return {
			projectLicense: {
				manifest: manifestLicenseInfo,
				file: fileLicenseInfo,
				mismatch: finalMismatch
			},
			incompatibleDependencies: [],
			error: 'No license data available in analysis report'
		};
	}

	// Use backend category from project license details (prefer manifest, fallback to file)
	const projectCategory = manifestLicenseInfo?.category || fileLicenseInfo?.category || null;
	const incompatibleDependencies = [];

	for (const purl of purls) {
		const entry = licenseByPurl.get(purl) || { licenses: [], category: undefined };
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
		projectLicense: {
			manifest: manifestLicenseInfo,
			file: fileLicenseInfo,
			mismatch: finalMismatch
		},
		incompatibleDependencies
	};
}
