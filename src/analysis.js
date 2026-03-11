import fs from "node:fs";
import path from "node:path";
import { EOL } from "os";

import { runLicenseCheck } from "./license/index.js";
import { generateImageSBOM, parseImageRef } from "./oci_image/utils.js";
import { addProxyAgent, getCustom, getTokenHeaders , TRUSTIFY_DA_OPERATION_TYPE_HEADER, TRUSTIFY_DA_PACKAGE_MANAGER_HEADER } from "./tools.js";

export default { requestComponent, requestStack, requestImages, validateToken }

/**
 * Send a stack analysis request and get the report as 'text/html' or 'application/json'.
 * @param {import('./provider').Provider} provider - the provided data for constructing the request
 * @param {string} manifest - path for the manifest
 * @param {string} url - the backend url to send the request to
 * @param {boolean} [html=false] - true will return 'text/html', false will return 'application/json'
 * @param {import("index.js").Options} [opts={}] - optional various options to pass along the application
 * @returns {Promise<string|import('@trustify-da/trustify-da-api-model/model/v5/AnalysisReport').AnalysisReport>}
 */
async function requestStack(provider, manifest, url, html = false, opts = {}) {
	opts["source-manifest"] = Buffer.from(fs.readFileSync(manifest).toString()).toString('base64')
	opts["manifest-type"] = path.parse(manifest).base
	let provided = await provider.provideStack(manifest, opts) // throws error if content providing failed
	opts["source-manifest"] = ""
	opts[TRUSTIFY_DA_OPERATION_TYPE_HEADER.toUpperCase().replaceAll("-", "_")] = "stack-analysis"
	let startTime = new Date()
	let endTime
	if (process.env["TRUSTIFY_DA_DEBUG"] === "true") {
		console.log("Starting time of sending stack analysis request to the dependency analytics server= " + startTime)
	}
	opts[TRUSTIFY_DA_PACKAGE_MANAGER_HEADER.toUpperCase().replaceAll("-", "_")] = provided.ecosystem

	const fetchOptions = addProxyAgent({
		method: 'POST',
		headers: {
			'Accept': html ? 'text/html' : 'application/json',
			'Content-Type': provided.contentType,
			...getTokenHeaders(opts),
		},
		body: provided.content
	}, opts);

	const finalUrl = new URL(`${url}/api/v5/analysis`);
	if (opts['TRUSTIFY_DA_RECOMMENDATIONS_ENABLED'] === 'false') {
		finalUrl.searchParams.append('recommend', 'false');
	}

	let resp = await fetch(finalUrl, fetchOptions)
	let result
	if (resp.status === 200) {
		if (!html) {
			result = await resp.json()
		} else {
			result = await resp.text()
		}
		if (process.env["TRUSTIFY_DA_DEBUG"] === "true") {
			let exRequestId = resp.headers.get("ex-request-id");
			if (exRequestId) {
				console.log("Unique Identifier associated with this request - ex-request-id=" + exRequestId)
			}
			endTime = new Date()
			console.log("Response body received from Trustify DA backend server : " + EOL + EOL)
			console.log(console.log(JSON.stringify(result, null, 4)))
			console.log("Ending time of sending stack analysis request to Trustify DA backend server= " + endTime)
			let time = (endTime - startTime) / 1000
			console.log("Total Time in seconds: " + time)

		}
	} else {
		throw new Error(`Got error response from Trustify DA backend - http return code : ${resp.status},  error message =>  ${await resp.text()}`)
	}

	return Promise.resolve(result)
}

/**
 * Send a component analysis request and get the report as 'application/json'.
 * @param {import('./provider').Provider} provider - the provided data for constructing the request
 * @param {string} manifest - path for the manifest
 * @param {string} url - the backend url to send the request to
 * @param {import("index.js").Options} [opts={}] - optional various options to pass along the application
 * @returns {Promise<import('@trustify-da/trustify-da-api-model/model/v5/AnalysisReport').AnalysisReport>}
 */
async function requestComponent(provider, manifest, url, opts = {}) {
	opts["source-manifest"] = Buffer.from(fs.readFileSync(manifest).toString()).toString('base64')

	let provided = await provider.provideComponent(manifest, opts) // throws error if content providing failed
	opts["source-manifest"] = ""
	opts[TRUSTIFY_DA_OPERATION_TYPE_HEADER.toUpperCase().replaceAll("-", "_")] = "component-analysis"
	if (process.env["TRUSTIFY_DA_DEBUG"] === "true") {
		console.log("Starting time of sending component analysis request to Trustify DA backend server= " + new Date())
	}
	opts[TRUSTIFY_DA_PACKAGE_MANAGER_HEADER.toUpperCase().replaceAll("-", "_")] = provided.ecosystem

	const fetchOptions = addProxyAgent({
		method: 'POST',
		headers: {
			'Accept': 'application/json',
			'Content-Type': provided.contentType,
			...getTokenHeaders(opts),
		},
		body: provided.content
	}, opts);

	const finalUrl = new URL(`${url}/api/v5/analysis`);
	if (opts['TRUSTIFY_DA_RECOMMENDATIONS_ENABLED'] === 'false') {
		finalUrl.searchParams.append('recommend', 'false');
	}

	let resp = await fetch(finalUrl, fetchOptions)
	let result
	if (resp.status === 200) {
		result = await resp.json()
		if (process.env["TRUSTIFY_DA_DEBUG"] === "true") {
			let exRequestId = resp.headers.get("ex-request-id");
			if (exRequestId) {
				console.log("Unique Identifier associated with this request - ex-request-id=" + exRequestId)
			}
			console.log("Response body received from Trustify DA backend server : " + EOL + EOL)
			console.log(JSON.stringify(result, null, 4))
			console.log("Ending time of sending component analysis request to Trustify DA backend server= " + new Date())


		}
		const licenseCheckEnabled = getCustom('TRUSTIFY_DA_LICENSE_CHECK', 'true', opts) !== 'false' && opts.licenseCheck !== false
		if (licenseCheckEnabled) {
			try {
				result.licenseSummary = await runLicenseCheck(provided.content, manifest, url, opts, result)
			} catch (licenseErr) {
				result.licenseSummary = { error: licenseErr.message }
			}
		}
	} else {
		throw new Error(`Got error response from Trustify DA backend - http return code : ${resp.status}, ex-request-id: ${resp.headers.get("ex-request-id")}  error message =>  ${await resp.text()}`)
	}

	return Promise.resolve(result)
}

/**
 *
 * @param {Array<string>} imageRefs
 * @param {string} url
 * @param {import("index.js").Options} [opts={}] - optional various options to pass along the application
 * @returns {Promise<string|Object.<string, import('@trustify-da/trustify-da-api-model/model/v5/AnalysisReport').AnalysisReport>>}
 */
async function requestImages(imageRefs, url, html = false, opts = {}) {
	const imageSboms = {}
	for (const image of imageRefs) {
		const parsedImageRef = parseImageRef(image, opts)
		imageSboms[parsedImageRef.getPackageURL().toString()] = generateImageSBOM(parsedImageRef, opts)
	}

	const finalUrl = new URL(`${url}/api/v5/batch-analysis`);
	if (opts['TRUSTIFY_DA_RECOMMENDATIONS_ENABLED'] === 'false') {
		finalUrl.searchParams.append('recommend', 'false');
	}

	const resp = await fetch(finalUrl, {
		method: 'POST',
		headers: {
			'Accept': html ? 'text/html' : 'application/json',
			'Content-Type': 'application/vnd.cyclonedx+json',
			...getTokenHeaders(opts)
		},
		body: JSON.stringify(imageSboms),
	})

	if (resp.status === 200) {
		let result;
		if (!html) {
			result = await resp.json()
		} else {
			result = await resp.text()
		}
		if (process.env["TRUSTIFY_DA_DEBUG"] === "true") {
			let exRequestId = resp.headers.get("ex-request-id");
			if (exRequestId) {
				console.log("Unique Identifier associated with this request - ex-request-id=" + exRequestId)
			}
			console.log("Response body received from Trustify DA backend server : " + EOL + EOL)
			console.log(JSON.stringify(result, null, 4))
			console.log("Ending time of sending component analysis request to Trustify DA backend server= " + new Date())
		}
		return result
	} else {
		throw new Error(`Got error response from Trustify DA backend - http return code : ${resp.status}, ex-request-id: ${resp.headers.get("ex-request-id")}  error message =>  ${await resp.text()}`)
	}
}

/**
 *
 * @param url the backend url to send the request to
 * @param {import("index.js").Options} [opts={}] - optional various options to pass headers for t he validateToken Request
 * @return {Promise<number>} return the HTTP status Code of the response from the validate token request.
 */
async function validateToken(url, opts = {}) {
	const fetchOptions = addProxyAgent({
		method: 'GET',
		headers: {
			...getTokenHeaders(opts),
		}
	}, opts);

	let resp = await fetch(`${url}/api/v5/token`, fetchOptions)
	if (process.env["TRUSTIFY_DA_DEBUG"] === "true") {
		let exRequestId = resp.headers.get("ex-request-id");
		if (exRequestId) {
			console.log("Unique Identifier associated with this request - ex-request-id=" + exRequestId)
		}
	}
	return resp.status
}
