/**
 * Client for the Trustify DA backend License Analysis API (POST /api/v5/licenses).
 * The same license data shape is returned in the dependency analysis JSON report (result.licenses).
 * @see https://github.com/guacsec/trustify-dependency-analytics#license-analysis-apiv5licenses
 * @see https://github.com/guacsec/trustify-da-api-spec/blob/main/api/v5/openapi.yaml
 */

import { PackageURL } from 'packageurl-js';
import { selectTrustifyDABackend } from '../index.js';
import { addProxyAgent, getTokenHeaders } from '../tools.js';

/**
 * Fetch license details by SPDX identifier from the backend GET /api/v5/licenses/{spdx}.
 * Returns detailed information about a specific license including category, name, and text.
 *
 * @param {string} spdxId - SPDX identifier (e.g., "Apache-2.0", "MIT")
 * @param {import('../index.js').Options} [opts={}] - options (proxy, token, TRUSTIFY_DA_BACKEND_URL, etc.)
 * @returns {Promise<Object|null>} License details or null if not found
 */
export async function getLicenseDetails(spdxId, opts = {}) {
	if (!spdxId) {return null;}

	const url = selectTrustifyDABackend(opts);
	const finalUrl = new URL(`${url}/api/v5/licenses/${encodeURIComponent(spdxId)}`);

	const fetchOptions = addProxyAgent({
		method: 'GET',
		headers: {
			'Accept': 'application/json',
			...getTokenHeaders(opts)
		},
	}, opts);

	try {
		const resp = await fetch(finalUrl, fetchOptions);
		if (!resp.ok) {
			const errorText = await resp.text().catch(() => '');
			throw new Error(`HTTP ${resp.status}: ${errorText || resp.statusText}`);
		}
		return await resp.json();
	} catch (err) {
		throw new Error(`Failed to fetch license details: ${err.message}`);
	}
}

function normalizePurlString(purl) {
	const parsed = PackageURL.fromString(purl);
	return new PackageURL(parsed.type, parsed.namespace, parsed.name, parsed.version, null, null).toString();
}

/**
 * Normalize the LicensesResponse shape (array of LicenseProviderResult) into a map of purl -> license info.
 * Each provider result has { status, summary, packages } where packages is { [purl]: { concluded, evidence } }.
 * We merge the first successful provider's packages; concluded has identifiers[], category (PERMISSIVE | WEAK_COPYLEFT | STRONG_COPYLEFT | UNKNOWN).
 *
 * @param {unknown} data - LicensesResponse (array) or analysis report's licenses field
 * @param {string[]} [purls] - optional list of purls to restrict to (for consistency with getLicensesByPurl)
 * @returns {Map<string, { licenses: string[], category?: string }>}
 */
export function normalizeLicensesResponse(data, purls = []) {
	const map = new Map();
	if (!data || !Array.isArray(data)) {return map;}

	const normalizedPurlsSet = purls.length > 0 ? new Set(purls.map(normalizePurlString)) : null;

	for (const providerResult of data) {
		const packages = providerResult?.packages;
		if (!packages || typeof packages !== 'object') {continue;}
		for (const [purl, pkgLicense] of Object.entries(packages)) {
			const concluded = pkgLicense?.concluded;
			const identifiers = Array.isArray(concluded?.identifiers) ? concluded.identifiers : [];
			const expression = concluded?.expression;
			const licenses = identifiers.length > 0 ? identifiers : (expression ? [expression] : []);
			const category = concluded?.category; // PERMISSIVE | WEAK_COPYLEFT | STRONG_COPYLEFT | UNKNOWN
			const normalizedPurl = normalizePurlString(purl);
			if (normalizedPurlsSet === null || normalizedPurlsSet.has(normalizedPurl)) {
				map.set(normalizedPurl, { licenses: licenses.filter(Boolean), category });
			}
		}
		// Use first provider that has packages; backend may return multiple (e.g. deps.dev)
		if (map.size > 0) {break;}
	}
	return map;
}

/**
 * Build license map from an analysis report that already includes license data (result.licenses).
 * Use this when the dependency analysis response already contains the licenses array to avoid a second request.
 *
 * @param {import('@trustify-da/trustify-da-api-model/model/v5/AnalysisReport').AnalysisReport} analysisReport - full analysis JSON
 * @param {string[]} [purls] - optional list of purls to restrict to
 * @returns {Map<string, { licenses: string[], category?: string }>}
 */
export function licensesFromReport(analysisReport, purls = []) {
	if (!analysisReport?.licenses) {return new Map();}
	return normalizeLicensesResponse(analysisReport.licenses, purls);
}
