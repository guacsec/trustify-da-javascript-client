/**
 * License resolution and dependency license compatibility for component analysis.
 */

import { getProjectLicense, findLicenseFilePath, identifyLicenseViaBackend } from './project_license.js';
import { licenseMapFromAnalysisReport } from './licenses_api.js';
import { getCompatibility } from './compatibility.js';

export { getProjectLicense, getProjectLicenseFromManifest, findLicenseFilePath, identifyLicenseViaBackend } from './project_license.js';
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
 * Run full license check: resolve project license (with optional backend identification for LICENSE file),
 * get dependency licenses from analysis report, and compute incompatibilities.
 *
 * @param {string} sbomContent - CycloneDX SBOM JSON string (the one sent for component analysis)
 * @param {string} manifestPath - path to manifest
 * @param {string} backendUrl - Trustify DA backend base URL
 * @param {import('../index.js').Options} [opts={}]
 * @param {import('@trustify-da/trustify-da-api-model/model/v5/AnalysisReport').AnalysisReport} [analysisResult] - analysis result that includes licenses array from backend
 * @returns {Promise<{ projectLicenseFromManifest: string|null, projectLicenseFromFile: string|null, manifestVsFileMismatch: boolean, incompatibleDependencies: Array<{ purl: string, licenses: string[], category?: string, reason: string }>, dependencyLicenses: Array<{ purl: string, licenses: string[], category?: string }>, error?: string }>}
 */
export async function runLicenseCheck(sbomContent, manifestPath, backendUrl, opts = {}, analysisResult = null) {
	// Get project license from manifest (always available)
	const projectLicense = getProjectLicense(manifestPath, opts);

	// Try to get more accurate LICENSE file identification from backend
	let projectLicenseFromFileBackend = null;
	const licenseFilePath = findLicenseFilePath(manifestPath);
	if (licenseFilePath && backendUrl) {
		try {
			projectLicenseFromFileBackend = await identifyLicenseViaBackend(licenseFilePath, backendUrl, opts);
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

	const purls = extractPurlsFromSbom(sbomContent, true);
	if (purls.length === 0) {
		return {
			projectLicenseFromManifest: projectLicense.fromManifest,
			projectLicenseFromFile: finalFromFile,
			manifestVsFileMismatch: finalMismatch,
			incompatibleDependencies: [],
			dependencyLicenses: []
		};
	}

	// Get dependency licenses from analysis report (backend already provides this)
	const licenseByPurl = licenseMapFromAnalysisReport(analysisResult, purls);
	if (licenseByPurl.size === 0 && analysisResult) {
		// No license data in analysis report - this might be expected for some backends
		return {
			projectLicenseFromManifest: projectLicense.fromManifest,
			projectLicenseFromFile: finalFromFile,
			manifestVsFileMismatch: finalMismatch,
			incompatibleDependencies: [],
			dependencyLicenses: [],
			error: 'No license data available in analysis report'
		};
	}

	const projectLicenseForCheck = projectLicense.fromManifest || finalFromFile || null;
	const dependencyLicenses = [];
	const incompatibleDependencies = [];

	for (const purl of purls) {
		const entry = licenseByPurl.get(purl) || { licenses: [], category: undefined };
		dependencyLicenses.push({ purl, licenses: entry.licenses, category: entry.category });
		const status = getCompatibility(projectLicenseForCheck, entry.licenses, entry.category);
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
		projectLicenseFromManifest: projectLicense.fromManifest,
		projectLicenseFromFile: finalFromFile,
		manifestVsFileMismatch: finalMismatch,
		incompatibleDependencies,
		dependencyLicenses
	};
}
