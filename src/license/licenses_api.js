/**
 * Client for the Trustify DA backend License Analysis API (POST /api/v5/licenses).
 * The same license data shape is returned in the dependency analysis JSON report (result.licenses).
 * @see https://github.com/guacsec/trustify-dependency-analytics#license-analysis-apiv5licenses
 * @see https://github.com/guacsec/trustify-da-api-spec/blob/main/api/v5/openapi.yaml
 */

import { HttpsProxyAgent } from 'https-proxy-agent';
import { getCustom } from '../tools.js';
import { getTokenHeaders } from '../tools.js';

/** Default path for the licenses endpoint (API v5). Override via TRUSTIFY_DA_LICENSES_API_PATH or opts. */
const DEFAULT_LICENSES_PATH = '/api/v5/licenses';

/**
 * Fetch license details by SPDX identifier from the backend GET /api/v5/licenses/{spdx}.
 * Returns detailed information about a specific license including category, name, and text.
 *
 * @param {string} spdxId - SPDX identifier (e.g., "Apache-2.0", "MIT")
 * @param {string} backendUrl - base URL of the Trustify DA backend (no trailing slash)
 * @param {import('../index.js').Options} [opts={}] - options (proxy, token, etc.)
 * @returns {Promise<Object|null>} License details or null if not found
 */
export async function getLicenseDetails(spdxId, backendUrl, opts = {}) {
	if (!spdxId) return null;

	const url = `${backendUrl.replace(/\/$/, '')}/api/v5/licenses/${encodeURIComponent(spdxId)}`;

	const fetchOptions = {
		method: 'GET',
		headers: {
			'Accept': 'application/json',
			...getTokenHeaders(opts)
		},
	};

	const proxyUrl = getCustom('TRUSTIFY_DA_PROXY_URL', null, opts);
	if (proxyUrl) {
		fetchOptions.agent = new HttpsProxyAgent(proxyUrl);
	}

	try {
		const resp = await fetch(url, fetchOptions);
		if (!resp.ok) {
			const errorText = await resp.text().catch(() => '');
			throw new Error(`HTTP ${resp.status}: ${errorText || resp.statusText}`);
		}
		return await resp.json();
	} catch (err) {
		throw new Error(`Failed to fetch license details: ${err.message}`);
	}
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
	if (!data || !Array.isArray(data)) return map;

	for (const providerResult of data) {
		const packages = providerResult?.packages;
		if (!packages || typeof packages !== 'object') continue;
		for (const [purl, pkgLicense] of Object.entries(packages)) {
			const concluded = pkgLicense?.concluded;
			const identifiers = Array.isArray(concluded?.identifiers) ? concluded.identifiers : [];
			const expression = concluded?.expression;
			const licenses = identifiers.length > 0 ? identifiers : (expression ? [expression] : []);
			const category = concluded?.category; // PERMISSIVE | WEAK_COPYLEFT | STRONG_COPYLEFT | UNKNOWN
			if (purls.length === 0 || purls.includes(purl)) {
				map.set(purl, { licenses: licenses.filter(Boolean), category });
			}
		}
		// Use first provider that has packages; backend may return multiple (e.g. deps.dev)
		if (map.size > 0) break;
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
export function licenseMapFromAnalysisReport(analysisReport, purls = []) {
	if (!analysisReport?.licenses) return new Map();
	return normalizeLicensesResponse(analysisReport.licenses, purls);
}

/**
 * Fetch licenses for the given purls from the backend POST /api/v5/licenses.
 * Request body: { purls: string[] }. Response: LicensesResponse (array of LicenseProviderResult).
 *
 * NOTE: This is typically not needed since dependency licenses are included in the analysis response.
 * Use licenseMapFromAnalysisReport() instead when you have an analysis result.
 *
 * @param {string[]} purls - array of purl strings (e.g. from SBOM components)
 * @param {string} backendUrl - base URL of the Trustify DA backend (no trailing slash)
 * @param {import('../index.js').Options} [opts={}] - options (proxy, token, etc.)
 * @returns {Promise<Map<string, { licenses: string[], category?: string }>>}
 */
export async function getLicensesByPurl(purls, backendUrl, opts = {}) {
	if (!purls || purls.length === 0) {
		return new Map();
	}

	const pathSegment = getCustom('TRUSTIFY_DA_LICENSES_API_PATH', DEFAULT_LICENSES_PATH, opts);
	const url = `${backendUrl.replace(/\/$/, '')}${pathSegment}`;

	const fetchOptions = {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'Accept': 'application/json',
			...getTokenHeaders(opts)
		},
		body: JSON.stringify({ purls }),
	};

	const proxyUrl = getCustom('TRUSTIFY_DA_PROXY_URL', null, opts);
	if (proxyUrl) {
		fetchOptions.agent = new HttpsProxyAgent(proxyUrl);
	}

	const resp = await fetch(url, fetchOptions);
	if (!resp.ok) {
		const text = await resp.text();
		throw new Error(`Licenses API failed: ${resp.status} ${text}`);
	}

	const data = await resp.json();
	return normalizeLicensesResponse(data, purls);
}
