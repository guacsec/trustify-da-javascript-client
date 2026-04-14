import path from "node:path";
import { EOL } from "os";
import pLimit from 'p-limit'

import { availableProviders, match } from './provider.js'
import analysis from './analysis.js'
import fs from 'node:fs'
import { getCustom } from "./tools.js";
import { resolveBatchMetadata, resolveContinueOnError } from './batch_opts.js'
import {
	discoverWorkspaceCrates,
	discoverWorkspacePackages,
	filterManifestPathsByDiscoveryIgnore,
	resolveWorkspaceDiscoveryIgnore,
	validatePackageJson,
} from './workspace.js'
import.meta.dirname
import * as url from 'url';

export { parseImageRef } from "./oci_image/utils.js";
export { ImageRef } from "./oci_image/images.js";
export { getProjectLicense, findLicenseFilePath, identifyLicense, getLicenseDetails, licensesFromReport, normalizeLicensesResponse, runLicenseCheck, getCompatibility } from "./license/index.js";

export default { componentAnalysis, stackAnalysis, stackAnalysisBatch, imageAnalysis, validateToken, generateSbom }
export {
	discoverWorkspacePackages,
	discoverWorkspaceCrates,
	validatePackageJson,
	resolveWorkspaceDiscoveryIgnore,
	filterManifestPathsByDiscoveryIgnore,
	resolveContinueOnError,
	resolveBatchMetadata,
}

/**
 * @typedef {{
 * TRUSTIFY_DA_CARGO_PATH?: string | undefined,
 * TRUSTIFY_DA_DOCKER_PATH?: string | undefined,
 * TRUSTIFY_DA_GO_MVS_LOGIC_ENABLED?: string | undefined,
 * TRUSTIFY_DA_GO_PATH?: string | undefined,
 * TRUSTIFY_DA_GRADLE_PATH?: string | undefined,
 * TRUSTIFY_DA_IMAGE_PLATFORM?: string | undefined,
 * TRUSTIFY_DA_MVN_PATH?: string | undefined,
 * TRUSTIFY_DA_PIP_PATH?: string | undefined,
 * TRUSTIFY_DA_PIP_USE_DEP_TREE?: string | undefined,
 * TRUSTIFY_DA_PIP3_PATH?: string | undefined,
 * TRUSTIFY_DA_PNPM_PATH?: string | undefined,
 * TRUSTIFY_DA_PODMAN_PATH?: string | undefined,
 * TRUSTIFY_DA_PREFER_GRADLEW?: string | undefined,
 * TRUSTIFY_DA_PREFER_MVNW?: string | undefined,
 * TRUSTIFY_DA_PROXY_URL?: string | undefined,
 * TRUSTIFY_DA_PYTHON_INSTALL_BEST_EFFORTS?: string | undefined,
 * TRUSTIFY_DA_PYTHON_PATH?: string | undefined,
 * TRUSTIFY_DA_PYTHON_VIRTUAL_ENV?: string | undefined,
 * TRUSTIFY_DA_PYTHON3_PATH?: string | undefined,
 * TRUSTIFY_DA_RECOMMENDATIONS_ENABLED?: string | undefined,
 * TRUSTIFY_DA_SKOPEO_CONFIG_PATH?: string | undefined,
 * TRUSTIFY_DA_SKOPEO_PATH?: string | undefined,
 * TRUSTIFY_DA_SYFT_CONFIG_PATH?: string | undefined,
 * TRUSTIFY_DA_SYFT_PATH?: string | undefined,
 * TRUSTIFY_DA_YARN_PATH?: string | undefined,
 * TRUSTIFY_DA_WORKSPACE_DIR?: string | undefined,
 * TRUSTIFY_DA_LICENSE_CHECK?: string | undefined,
 * MATCH_MANIFEST_VERSIONS?: string | undefined,
 * TRUSTIFY_DA_SOURCE?: string | undefined,
 * TRUSTIFY_DA_TOKEN?: string | undefined,
 * TRUSTIFY_DA_TELEMETRY_ID?: string | undefined,
 * TRUSTIFY_DA_WORKSPACE_DIR?: string | undefined,
 * batchConcurrency?: number | undefined,
 * TRUSTIFY_DA_BATCH_CONCURRENCY?: string | undefined,
 * workspaceDiscoveryIgnore?: string[] | undefined,
 * TRUSTIFY_DA_WORKSPACE_DISCOVERY_IGNORE?: string | undefined,
 * continueOnError?: boolean | undefined,
 * TRUSTIFY_DA_CONTINUE_ON_ERROR?: string | undefined,
 * batchMetadata?: boolean | undefined,
 * TRUSTIFY_DA_BATCH_METADATA?: string | undefined,
 * TRUSTIFY_DA_UV_PATH?: string | undefined,
 * TRUSTIFY_DA_POETRY_PATH?: string | undefined,
 * [key: string]: string | number | boolean | string[] | undefined,
 * }} Options
 */

/**
 * @typedef {{
 *   workspaceRoot: string,
 *   ecosystem: 'javascript' | 'cargo' | 'unknown',
 *   total: number,
 *   successful: number,
 *   failed: number,
 *   errors: Array<{ manifestPath: string, phase: 'validation' | 'sbom', reason: string }>
 * }} BatchAnalysisMetadata
 */


/**
 * Logs messages to the console if the TRUSTIFY_DA_DEBUG environment variable is set to "true".
 * @param {string} alongsideText - The text to prepend to the log message.
 * @param {any} valueToBePrinted - The value to log.
 * @private
 */
function logOptionsAndEnvironmentsVariables(alongsideText,valueToBePrinted) {
	if (process.env["TRUSTIFY_DA_DEBUG"] === "true") {
		console.log(`${alongsideText}: ${valueToBePrinted} ${EOL}`)
	}
}

/**
 * Reads the version from the package.json file and logs it if debug mode is enabled.
 * @private
 */
function readAndPrintVersionFromPackageJson() {
	let dirName
// new ESM way in nodeJS ( since node version 22 ) to bring module directory.
	dirName = import.meta.dirname
// old ESM way in nodeJS ( before node versions 22.00 to bring module directory)
	if (!dirName) {
		dirName = url.fileURLToPath(new URL('.', import.meta.url));
	}

	try {
		if (__dirname) {
			dirName = __dirname;
		}
	} catch (e) {
		console.log("__dirname is not defined, continue with fileUrlPath")
	}

	let packageJson = JSON.parse(fs.readFileSync(path.join(dirName, "..", "package.json")).toString())
	logOptionsAndEnvironmentsVariables("trustify-da-javascript-client analysis started, version: ", packageJson.version)
}

/**
 * This function is used to determine the Trustify DA backend URL.
 * The TRUSTIFY_DA_BACKEND_URL is evaluated in the following order and selected when it finds it first:
 * 1. Environment Variable
 * 2. (key,value) from opts object
 * If TRUSTIFY_DA_BACKEND_URL is not set, the function will throw an error.
 * @param {{TRUSTIFY_DA_DEBUG?: string | undefined; TRUSTIFY_DA_BACKEND_URL?: string | undefined}} [opts={}]
 * @return {string} - The selected Trustify DA backend URL
 * @throws {Error} if TRUSTIFY_DA_BACKEND_URL is unset
 * @private
 */
export function selectTrustifyDABackend(opts = {}) {
	if (getCustom("TRUSTIFY_DA_DEBUG", "false", opts) === "true") {
		readAndPrintVersionFromPackageJson();
	}

	let url = getCustom('TRUSTIFY_DA_BACKEND_URL', null, opts);
	if (!url) {
		throw new Error(`TRUSTIFY_DA_BACKEND_URL is unset`)
	}

	logOptionsAndEnvironmentsVariables("Chosen Trustify DA backend URL:", url)

	return url;
}

/**
 * @overload
 * @param {string} manifest
 * @param {true} html
 * @param {Options} [opts={}]
 * @returns {Promise<string>}
 * @throws {Error}
 */

/**
 * @overload
 * @param {string} manifest
 * @param {false} html
 * @param {Options} [opts={}]
 * @returns {Promise<import('@trustify-da/trustify-da-api-model/model/v5/AnalysisReport').AnalysisReport>}
 * @throws {Error}
 */

/**
 * Get stack analysis report for a manifest file.
 * @overload
 * @param {string} manifest - path for the manifest
 * @param {boolean} [html=false] - true will return a html string, false will return AnalysisReport object.
 * @param {Options} [opts={}] - optional various options to pass along the application
 * @returns {Promise<string|import('@trustify-da/trustify-da-api-model/model/v5/AnalysisReport').AnalysisReport>}
 * @throws {Error} if manifest inaccessible, no matching provider, failed to get create content,
 * 		or backend request failed
 */
async function stackAnalysis(manifest, html = false, opts = {}) {
	const theUrl = selectTrustifyDABackend(opts)
	fs.accessSync(manifest, fs.constants.R_OK) // throws error if file unreadable
	let provider = match(manifest, availableProviders, opts) // throws error if no matching provider
	return await analysis.requestStack(provider, manifest, theUrl, html, opts) // throws error request sending failed
}

/**
 * Get component analysis report for a manifest content.
 * @param {string} manifest - path to the manifest
 * @param {Options} [opts={}] - optional various options to pass along the application
 * @returns {Promise<import('@trustify-da/trustify-da-api-model/model/v5/AnalysisReport').AnalysisReport>}
 * @throws {Error} if no matching provider, failed to get create content, or backend request failed
 */
async function componentAnalysis(manifest, opts = {}) {
	const theUrl = selectTrustifyDABackend(opts)
	fs.accessSync(manifest, fs.constants.R_OK)
	opts["manifest-type"] = path.basename(manifest)
	let provider = match(manifest, availableProviders, opts) // throws error if no matching provider
	return await analysis.requestComponent(provider, manifest, theUrl, opts) // throws error request sending failed
}

/**
 * @overload
 * @param {Array<string>} imageRefs
 * @param {true} html
 * @param {Options} [opts={}]
 * @returns {Promise<string>}
 * @throws {Error}
 */

/**
 * @overload
 * @param {Array<string>} imageRefs
 * @param {false} html
 * @param {Options} [opts={}]
 * @returns {Promise<Object.<string, import('@trustify-da/trustify-da-api-model/model/v5/AnalysisReport').AnalysisReport>>}
 * @throws {Error}
 */

/**
 * Get image analysis report for a set of OCI image references.
 * @overload
 * @param {Array<string>} imageRefs - OCI image references
 * @param {boolean} [html=false] - true will return a html string, false will return AnalysisReport
 * @param {Options} [opts={}] - optional various options to pass along the application
 * @returns {Promise<string|Object.<string, import('@trustify-da/trustify-da-api-model/model/v5/AnalysisReport').AnalysisReport>>}
 * @throws {Error} if manifest inaccessible, no matching provider, failed to get create content,
 * 		or backend request failed
 */
async function imageAnalysis(imageRefs, html = false, opts = {}) {
	const theUrl = selectTrustifyDABackend(opts)
	return await analysis.requestImages(imageRefs, theUrl, html, opts)
}

/**
 * Max concurrent SBOM generations for batch workspace analysis. Env/opts override default 10.
 * @param {Options} opts
 * @returns {number}
 * @private
 */
function resolveBatchConcurrency(opts) {
	const fromEnv = getCustom('TRUSTIFY_DA_BATCH_CONCURRENCY', null, opts)
	const raw = opts.batchConcurrency ?? fromEnv ?? '10'
	const n = typeof raw === 'number' ? raw : parseInt(String(raw), 10)
	if (!Number.isFinite(n) || n < 1) {
		return 10
	}
	return Math.min(256, n)
}

/**
 * @param {string} root
 * @param {'javascript' | 'cargo' | 'unknown'} ecosystem
 * @param {number} totalSbomAttempts
 * @param {number} successfulSbomCount
 * @param {Array<{ manifestPath: string, phase: 'validation' | 'sbom', reason: string }>} errors
 * @returns {BatchAnalysisMetadata}
 * @private
 */
function buildBatchAnalysisMetadata(root, ecosystem, totalSbomAttempts, successfulSbomCount, errors) {
	return {
		workspaceRoot: root,
		ecosystem,
		total: totalSbomAttempts,
		successful: successfulSbomCount,
		failed: errors.length,
		errors: [...errors],
	}
}

/**
 * Generate a CycloneDX SBOM from a manifest file. No backend HTTP request is made.
 *
 * @param {string} manifestPath - path to the manifest file (e.g. pom.xml, package.json)
 * @param {Options} [opts={}] - optional options (e.g. workspace dir, tool paths)
 * @returns {Promise<object>} parsed CycloneDX SBOM JSON object
 * @throws {Error} if the manifest is unsupported or SBOM generation fails
 */
export async function generateSbom(manifestPath, opts = {}) {
	fs.accessSync(manifestPath, fs.constants.R_OK)
	const result = await generateOneSbom(manifestPath, opts)
	if (!result.ok) {
		throw new Error(`Failed to generate SBOM for ${result.manifestPath}: ${result.reason}`)
	}
	return result.sbom
}

/**
 * @typedef {{ ok: true, purl: string, sbom: object } | { ok: false, manifestPath: string, reason: string }} SbomResult
 */

/**
 * Generate an SBOM for a single manifest, returning a normalized result.
 *
 * @param {string} manifestPath
 * @param {Options} workspaceOpts - opts with `TRUSTIFY_DA_WORKSPACE_DIR` set
 * @returns {Promise<SbomResult>}
 * @private
 */
async function generateOneSbom(manifestPath, workspaceOpts) {
	const provider = match(manifestPath, availableProviders, workspaceOpts)
	const provided = await provider.provideStack(manifestPath, workspaceOpts)
	const sbom = JSON.parse(provided.content)
	const purl = sbom?.metadata?.component?.purl || sbom?.metadata?.component?.['bom-ref']
	if (!purl) {
		return { ok: false, manifestPath, reason: 'missing purl in SBOM' }
	}
	return { ok: true, purl, sbom }
}

/**
 * Detect the workspace ecosystem and discover manifest paths.
 *
 * @param {string} root - Resolved workspace root
 * @param {Options} opts
 * @returns {Promise<{ ecosystem: 'javascript' | 'cargo' | 'unknown', manifestPaths: string[] }>}
 * @private
 */
async function detectWorkspaceManifests(root, opts) {
	const cargoToml = path.join(root, 'Cargo.toml')
	const cargoLock = path.join(root, 'Cargo.lock')
	const packageJson = path.join(root, 'package.json')

	if (fs.existsSync(cargoToml) && fs.existsSync(cargoLock)) {
		return { ecosystem: 'cargo', manifestPaths: await discoverWorkspaceCrates(root, opts) }
	}

	const hasJsLock = fs.existsSync(path.join(root, 'pnpm-lock.yaml'))
		|| fs.existsSync(path.join(root, 'yarn.lock'))
		|| fs.existsSync(path.join(root, 'package-lock.json'))

	if (fs.existsSync(packageJson) && hasJsLock) {
		let manifestPaths = await discoverWorkspacePackages(root, opts)
		if (manifestPaths.length === 0) {
			manifestPaths = [packageJson]
		}
		return { ecosystem: 'javascript', manifestPaths }
	}

	return { ecosystem: 'unknown', manifestPaths: [] }
}

/**
 * Validate discovered JS package.json manifests, collecting errors.
 *
 * @param {string[]} manifestPaths
 * @param {boolean} continueOnError
 * @param {Array<{ manifestPath: string, phase: 'validation' | 'sbom', reason: string }>} collectedErrors - mutated in place
 * @returns {{ validPaths: string[] }}
 * @throws {Error} on first invalid manifest when `continueOnError` is false
 * @private
 */
function validateJsManifests(manifestPaths, continueOnError, collectedErrors) {
	const validPaths = []
	for (const p of manifestPaths) {
		const v = validatePackageJson(p)
		if (v.valid) {
			validPaths.push(p)
		} else {
			collectedErrors.push({ manifestPath: p, phase: 'validation', reason: v.error })
			console.warn(`Skipping invalid package.json (${v.error}): ${p}`)
			if (!continueOnError) {
				throw new Error(`Invalid package.json (${v.error}): ${p}`)
			}
		}
	}
	return { validPaths }
}

/**
 * Generate SBOMs for all manifests. In fail-fast mode, stops on first error.
 * In continue-on-error mode, runs concurrently and collects failures.
 *
 * @param {string[]} manifestPaths
 * @param {Options} workspaceOpts
 * @param {boolean} continueOnError
 * @param {number} concurrency
 * @param {Array<{ manifestPath: string, phase: 'validation' | 'sbom', reason: string }>} collectedErrors - mutated in place
 * @returns {Promise<Object.<string, object>>} sbomByPurl map
 * @throws {Error} on first SBOM failure when `continueOnError` is false
 * @private
 */
async function generateSboms(manifestPaths, workspaceOpts, continueOnError, concurrency, collectedErrors) {
	/** @type {SbomResult[]} */
	const results = []

	if (!continueOnError) {
		for (const manifestPath of manifestPaths) {
			const result = await generateOneSbom(manifestPath, workspaceOpts)
			if (!result.ok) {
				collectedErrors.push({ manifestPath: result.manifestPath, phase: 'sbom', reason: result.reason })
				throw new Error(`${result.manifestPath}: ${result.reason}`)
			}
			results.push(result)
		}
	} else {
		const limit = pLimit(concurrency)
		const settled = await Promise.all(
			manifestPaths.map(manifestPath => limit(async () => {
				try {
					return await generateOneSbom(manifestPath, workspaceOpts)
				} catch (err) {
					const msg = err instanceof Error ? err.message : String(err)
					if (process.env["TRUSTIFY_DA_DEBUG"] === "true") {
						console.log(`Skipping ${manifestPath}: ${msg}`)
					}
					return { ok: false, manifestPath, reason: msg }
				}
			}))
		)
		for (const r of settled) {
			results.push(r)
			if (!r.ok) {
				collectedErrors.push({ manifestPath: r.manifestPath, phase: 'sbom', reason: r.reason })
			}
		}
	}

	const sbomByPurl = {}
	for (const r of results) {
		if (r.ok) {
			sbomByPurl[r.purl] = r.sbom
		}
	}
	return sbomByPurl
}

/**
 * Create an Error with optional `batchMetadata` attached.
 * @param {string} message
 * @param {boolean} wantMetadata
 * @param {BatchAnalysisMetadata} [metadata]
 * @returns {Error}
 * @private
 */
function batchError(message, wantMetadata, metadata) {
	const err = new Error(message)
	if (wantMetadata && metadata) {
		err.batchMetadata = metadata
	}
	return err
}

/**
 * Get stack analysis for all workspace packages/crates (batch).
 * Detects ecosystem from workspace root: Cargo (Cargo.toml + Cargo.lock) or JS/TS (package.json + lock file).
 * SBOMs are generated in parallel (see `batchConcurrency`) unless `continueOnError: false` (fail-fast sequential).
 * With `opts.batchMetadata` / `TRUSTIFY_DA_BATCH_METADATA`, returns `{ analysis, metadata }` including validation and SBOM errors.
 *
 * @param {string} workspaceRoot - Path to workspace root (containing lock file and workspace config)
 * @param {boolean} [html=false] - true returns HTML, false returns JSON report
 * @param {Options} [opts={}] - `batchConcurrency`, discovery ignores, `continueOnError` (default true), `batchMetadata` (default false)
 * @returns {Promise<string|Object.<string, import('@trustify-da/trustify-da-api-model/model/v5/AnalysisReport').AnalysisReport>|{ analysis: string|Object.<string, import('@trustify-da/trustify-da-api-model/model/v5/AnalysisReport').AnalysisReport>, metadata: BatchAnalysisMetadata }>}
 * @throws {Error} if workspace root invalid, no manifests found, no packages pass validation, no SBOMs produced, or backend request failed. When `opts.batchMetadata` is set, `error.batchMetadata` may be set on thrown errors.
 */
async function stackAnalysisBatch(workspaceRoot, html = false, opts = {}) {
	const theUrl = selectTrustifyDABackend(opts)
	const root = path.resolve(workspaceRoot)
	fs.accessSync(root, fs.constants.R_OK)

	const continueOnError = resolveContinueOnError(opts)
	const wantMetadata = resolveBatchMetadata(opts)

	/** @type {Array<{ manifestPath: string, phase: 'validation' | 'sbom', reason: string }>} */
	const collectedErrors = []

	const { ecosystem, manifestPaths: discovered } = await detectWorkspaceManifests(root, opts)
	let manifestPaths = discovered

	if (ecosystem === 'javascript') {
		try {
			const { validPaths } = validateJsManifests(manifestPaths, continueOnError, collectedErrors)
			manifestPaths = validPaths
		} catch (err) {
			throw batchError(err.message, wantMetadata,
				buildBatchAnalysisMetadata(root, ecosystem, 0, 0, collectedErrors))
		}
		if (manifestPaths.length === 0 && discovered.length > 0) {
			const detail = collectedErrors.map(e => `${e.manifestPath}: ${e.reason}`).join('; ')
			throw batchError(`No valid packages after validation at ${root}. ${detail}`, wantMetadata,
				buildBatchAnalysisMetadata(root, ecosystem, 0, 0, collectedErrors))
		}
	}

	if (manifestPaths.length === 0) {
		throw new Error(`No workspace manifests found at ${root}. Ensure Cargo.toml+Cargo.lock or package.json+lock file exist.`)
	}

	const workspaceOpts = { ...opts, TRUSTIFY_DA_WORKSPACE_DIR: root }
	const concurrency = resolveBatchConcurrency(opts)

	let sbomByPurl
	try {
		sbomByPurl = await generateSboms(manifestPaths, workspaceOpts, continueOnError, concurrency, collectedErrors)
	} catch (err) {
		throw batchError(err.message, wantMetadata,
			buildBatchAnalysisMetadata(root, ecosystem, manifestPaths.length, 0, collectedErrors))
	}

	if (Object.keys(sbomByPurl).length === 0) {
		throw batchError(
			`No valid SBOMs produced from ${manifestPaths.length} manifest(s) at ${root}`,
			wantMetadata,
			buildBatchAnalysisMetadata(root, ecosystem, manifestPaths.length, 0, collectedErrors)
		)
	}

	const analysisResult = await analysis.requestStackBatch(sbomByPurl, theUrl, html, opts)
	const meta = buildBatchAnalysisMetadata(
		root, ecosystem, manifestPaths.length, Object.keys(sbomByPurl).length, collectedErrors
	)

	if (wantMetadata) {
		return { analysis: analysisResult, metadata: meta }
	}
	return analysisResult
}

/**
 * Validates the Exhort token.
 * @param {Options} [opts={}] - Optional parameters, potentially including token override.
 * @returns {Promise<object>} A promise that resolves with the validation result from the backend.
 * @throws {Error} if the backend request failed.
 */
async function validateToken(opts = {}) {
	const theUrl = selectTrustifyDABackend(opts)
	return await analysis.validateToken(theUrl, opts) // throws error request sending failed
}
