import fs from "node:fs";
import path from "node:path";
import { EOL } from "os";

import { HttpsProxyAgent } from "https-proxy-agent";

import { generateImageSBOM, parseImageRef } from "./oci_image/utils.js";
import { RegexNotToBeLogged, getCustom } from "./tools.js";

export default { requestComponent, requestStack, requestImages, validateToken }

const rhdaTokenHeader = "rhda-token";
const rhdaTelemetryId = "rhda-telemetry-id";
const rhdaSourceHeader = "rhda-source"
const rhdaOperationTypeHeader = "rhda-operation-type"
const rhdaPackageManagerHeader = "rhda-pkg-manager"

/**
 * Adds proxy agent configuration to fetch options if a proxy URL is specified
 * @param {RequestInit} options - The base fetch options
 * @param {import("index.js").Options} opts - The exhort options that may contain proxy configuration
 * @returns {RequestInit} The fetch options with proxy agent if applicable
 */
function addProxyAgent(options, opts) {
	const proxyUrl = getCustom('TRUSTIFY_DA_PROXY_URL', null, opts);
	if (proxyUrl) {
		options.agent = new HttpsProxyAgent(proxyUrl);
	}
	return options;
}

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
	let provided = provider.provideStack(manifest, opts) // throws error if content providing failed
	opts["source-manifest"] = ""
	opts[rhdaOperationTypeHeader.toUpperCase().replaceAll("-", "_")] = "stack-analysis"
	let startTime = new Date()
	let endTime
	if (process.env["TRUSTIFY_DA_DEBUG"] === "true") {
		console.log("Starting time of sending stack analysis request to exhort server= " + startTime)
	}
	opts[rhdaPackageManagerHeader.toUpperCase().replaceAll("-", "_")] = provided.ecosystem

	const fetchOptions = addProxyAgent({
		method: 'POST',
		headers: {
			'Accept': html ? 'text/html' : 'application/json',
			'Content-Type': provided.contentType,
			...getTokenHeaders(opts),
		},
		body: provided.content
	}, opts);

	const finalUrl = new URL(`${url}/api/v4/analysis`);
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
			console.log("Response body received from exhort server : " + EOL + EOL)
			console.log(console.log(JSON.stringify(result, null, 4)))
			console.log("Ending time of sending stack analysis request to exhort server= " + endTime)
			let time = (endTime - startTime) / 1000
			console.log("Total Time in seconds: " + time)

		}
	} else {
		throw new Error(`Got error response from exhort backend - http return code : ${resp.status},  error message =>  ${await resp.text()}`)
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

	let provided = provider.provideComponent(manifest, opts) // throws error if content providing failed
	opts["source-manifest"] = ""
	opts[rhdaOperationTypeHeader.toUpperCase().replaceAll("-", "_")] = "component-analysis"
	if (process.env["TRUSTIFY_DA_DEBUG"] === "true") {
		console.log("Starting time of sending component analysis request to exhort server= " + new Date())
	}
	opts[rhdaPackageManagerHeader.toUpperCase().replaceAll("-", "_")] = provided.ecosystem

	const fetchOptions = addProxyAgent({
		method: 'POST',
		headers: {
			'Accept': 'application/json',
			'Content-Type': provided.contentType,
			...getTokenHeaders(opts),
		},
		body: provided.content
	}, opts);

	const finalUrl = new URL(`${url}/api/v4/analysis`);
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
			console.log("Response body received from exhort server : " + EOL + EOL)
			console.log(JSON.stringify(result, null, 4))
			console.log("Ending time of sending component analysis request to exhort server= " + new Date())


		}
	} else {
		throw new Error(`Got error response from exhort backend - http return code : ${resp.status}, ex-request-id: ${resp.headers.get("ex-request-id")}  error message =>  ${await resp.text()}`)
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

	const finalUrl = new URL(`${url}/api/v4/batch-analysis`);
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
			console.log("Response body received from exhort server : " + EOL + EOL)
			console.log(JSON.stringify(result, null, 4))
			console.log("Ending time of sending component analysis request to exhort server= " + new Date())
		}
		return result
	} else {
		throw new Error(`Got error response from exhort backend - http return code : ${resp.status}, ex-request-id: ${resp.headers.get("ex-request-id")}  error message =>  ${await resp.text()}`)
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

	let resp = await fetch(`${url}/api/v4/token`, fetchOptions)
	if (process.env["TRUSTIFY_DA_DEBUG"] === "true") {
		let exRequestId = resp.headers.get("ex-request-id");
		if (exRequestId) {
			console.log("Unique Identifier associated with this request - ex-request-id=" + exRequestId)
		}
	}
	return resp.status
}

/**
 *
 * @param {string} headerName - the header name to populate in request
 * @param headers
 * @param {import("index.js").Options} [opts={}] - optional various options to pass along the application
 * @private
 */
function setRhdaHeader(headerName, headers, opts) {
	let rhdaHeaderValue = getCustom(headerName.toUpperCase().replaceAll("-", "_"), null, opts);
	if (rhdaHeaderValue) {
		headers[headerName] = rhdaHeaderValue
	}
}

/**
 * Utility function for fetching vendor tokens
 * @param {import("index.js").Options} [opts={}] - optional various options to pass along the application
 * @returns {{}}
 */
function getTokenHeaders(opts = {}) {
	let supportedTokens = ['snyk', 'oss-index']
	let headers = {}
	supportedTokens.forEach(vendor => {
		let token = getCustom(`TRUSTIFY_DA_${vendor.replace("-", "_").toUpperCase()}_TOKEN`, null, opts);
		if (token) {
			headers[`ex-${vendor}-token`] = token
		}
		let user = getCustom(`TRUSTIFY_DA_${vendor.replace("-", "_").toUpperCase()}_USER`, null, opts);
		if (user) {
			headers[`ex-${vendor}-user`] = user
		}
	})
	setRhdaHeader(rhdaTokenHeader, headers, opts);
	setRhdaHeader(rhdaSourceHeader, headers, opts);
	setRhdaHeader(rhdaOperationTypeHeader, headers, opts);
	setRhdaHeader(rhdaPackageManagerHeader, headers, opts)
	setRhdaHeader(rhdaTelemetryId, headers, opts);

	if (process.env["TRUSTIFY_DA_DEBUG"] === "true") {
		console.log("Headers Values to be sent to exhort:" + EOL)
		for (const headerKey in headers) {
			if (!headerKey.match(RegexNotToBeLogged)) {
				console.log(`${headerKey}: ${headers[headerKey]}`)
			}
		}
	}
	return headers
}
