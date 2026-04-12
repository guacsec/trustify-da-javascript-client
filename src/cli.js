#!/usr/bin/env node

import fs from 'node:fs'
import * as path from "path";

import yargs from 'yargs'
import { hideBin } from 'yargs/helpers'

import { getProjectLicense, getLicenseDetails } from './license/index.js'

import client, { selectTrustifyDABackend, generateSbom } from './index.js'


// command for component analysis take manifest type and content
const component = {
	command: 'component </path/to/manifest>',
	desc: 'produce component report for manifest path',
	builder: yargs => yargs.positional(
		'/path/to/manifest',
		{
			desc: 'manifest path for analyzing',
			type: 'string',
			normalize: true,
		}
	).options({
		workspaceDir: {
			alias: 'w',
			desc: 'Workspace root directory (for monorepos; lock file is expected here)',
			type: 'string',
			normalize: true,
		}
	}),
	handler: async args => {
		let manifestName = args['/path/to/manifest']
		const opts = args.workspaceDir ? { TRUSTIFY_DA_WORKSPACE_DIR: args.workspaceDir } : {}
		let res = await client.componentAnalysis(manifestName, opts)
		console.log(JSON.stringify(res, null, 2))
	}
}
const validateToken = {
	command: 'validate-token <token-provider> [--token-value thevalue]',
	desc: 'Validates input token if authentic and authorized',
	builder: yargs => yargs.positional(
		'token-provider',
		{
			desc: 'the token provider name',
			type: 'string'
		}
	).options({
		tokenValue: {
			alias: 'value',
			desc: 'the actual token value to be checked',
			type: 'string',
		}
	}),
	handler: async args => {
		let tokenProvider = args['token-provider'].toUpperCase()
		let opts={}
		if(args['tokenValue'] !== undefined && args['tokenValue'].trim() !=="" ) {
			let tokenValue = args['tokenValue'].trim()
			opts[`TRUSTIFY_DA_PROVIDER_${tokenProvider}_TOKEN`] = tokenValue
		}
		let res = await client.validateToken(opts)
		console.log(res)
	}
}

// command for image analysis takes OCI image references
const image = {
	command: 'image <image-refs..>',
	desc: 'produce image analysis report for OCI image references',
	builder: yargs => yargs.positional(
		'image-refs',
		{
			desc: 'OCI image references to analyze (one or more)',
			type: 'string',
			array: true,
		}
	).options({
		html: {
			alias: 'r',
			desc: 'Get the report as HTML instead of JSON',
			type: 'boolean',
			conflicts: 'summary'
		},
		summary: {
			alias: 's',
			desc: 'For JSON report, get only the \'summary\'',
			type: 'boolean',
			conflicts: 'html'
		}
	}),
	handler: async args => {
		let imageRefs = args['image-refs']
		if (!Array.isArray(imageRefs)) {
			imageRefs = [imageRefs]
		}
		let html = args['html']
		let summary = args['summary']
		let res = await client.imageAnalysis(imageRefs, html)
		if(summary && !html) {
			let summaries = {}
			for (let [imageRef, report] of Object.entries(res)) {
				for (let provider in report.providers) {
					if (report.providers[provider].sources !== undefined) {
						for (let source in report.providers[provider].sources) {
							if (report.providers[provider].sources[source].summary) {
								if (!summaries[imageRef]) {
									summaries[imageRef] = {};
								}
								if (!summaries[imageRef][provider]) {
									summaries[imageRef][provider] = {};
								}
								summaries[imageRef][provider][source] = report.providers[provider].sources[source].summary
							}
						}
					}
				}
			}
			res = summaries
		}
		console.log(html ? res : JSON.stringify(res, null, 2))
	}
}

// command for stack analysis takes a manifest path
const stack = {
	command: 'stack </path/to/manifest> [--html|--summary]',
	desc: 'produce stack report for manifest path',
	builder: yargs => yargs.positional(
		'/path/to/manifest',
		{
			desc: 'manifest path for analyzing',
			type: 'string',
			normalize: true,
		}
	).options({
		html: {
			alias: 'r',
			desc: 'Get the report as HTML instead of JSON',
			type: 'boolean',
			conflicts: 'summary'
		},
		summary: {
			alias: 's',
			desc: 'For JSON report, get only the \'summary\'',
			type: 'boolean',
			conflicts: 'html'
		},
		workspaceDir: {
			alias: 'w',
			desc: 'Workspace root directory (for monorepos; lock file is expected here)',
			type: 'string',
			normalize: true,
		}
	}),
	handler: async args => {
		let manifest = args['/path/to/manifest']
		let html = args['html']
		let summary = args['summary']
		const opts = args.workspaceDir ? { TRUSTIFY_DA_WORKSPACE_DIR: args.workspaceDir } : {}
		let theProvidersSummary = new Map();
		let theProvidersObject ={}
		let res = await client.stackAnalysis(manifest, html, opts)
		if(summary)
		{
			for (let provider in res.providers ) {
				if (res.providers[provider].sources !== undefined) {
					for(let source in res.providers[provider].sources ) {
						if(res.providers[provider].sources[source].summary) {
							theProvidersSummary.set(source,res.providers[provider].sources[source].summary)
						}
					}
				}
			}
			for (let [provider, providerSummary] of theProvidersSummary) {
				theProvidersObject[provider]=providerSummary
			}
		}
		console.log(html ? res : JSON.stringify(
			!html && summary ? theProvidersObject : res,
			null,
			2
		))
	}
}

// command for batch stack analysis (workspace)
const stackBatch = {
	command: 'stack-batch </path/to/workspace-root> [--html|--summary] [--concurrency <n>] [--ignore <pattern>...] [--metadata] [--fail-fast]',
	desc: 'produce stack report for all packages/crates in a workspace (Cargo or JS/TS)',
	builder: yargs => yargs.positional(
		'/path/to/workspace-root',
		{
			desc: 'workspace root directory (containing Cargo.toml+Cargo.lock or package.json+lock file)',
			type: 'string',
			normalize: true,
		}
	).options({
		html: {
			alias: 'r',
			desc: 'Get the report as HTML instead of JSON',
			type: 'boolean',
			conflicts: 'summary'
		},
		summary: {
			alias: 's',
			desc: 'For JSON report, get only the \'summary\' per package',
			type: 'boolean',
			conflicts: 'html'
		},
		concurrency: {
			alias: 'c',
			desc: 'Max parallel SBOM generations (default: 10, env: TRUSTIFY_DA_BATCH_CONCURRENCY)',
			type: 'number',
		},
		ignore: {
			alias: 'i',
			desc: 'Extra glob patterns excluded from workspace discovery (merged with defaults). Repeat flag per pattern. Env: TRUSTIFY_DA_WORKSPACE_DISCOVERY_IGNORE (comma-separated)',
			type: 'string',
			array: true,
		},
		metadata: {
			alias: 'm',
			desc: 'Return { analysis, metadata } with per-manifest errors (env: TRUSTIFY_DA_BATCH_METADATA=true)',
			type: 'boolean',
			default: false,
		},
		failFast: {
			desc: 'Stop on first invalid package.json or SBOM error (env: TRUSTIFY_DA_CONTINUE_ON_ERROR=false)',
			type: 'boolean',
			default: false,
		}
	}),
	handler: async args => {
		const workspaceRoot = args['/path/to/workspace-root']
		const html = args['html']
		const summary = args['summary']
		const opts = {}
		if (args.concurrency != null) {
			opts.batchConcurrency = args.concurrency
		}
		const extraIgnores = Array.isArray(args.ignore) ? args.ignore.filter(p => p != null && String(p).trim()) : []
		if (extraIgnores.length > 0) {
			opts.workspaceDiscoveryIgnore = extraIgnores
		}
		if (args.metadata) {
			opts.batchMetadata = true
		}
		if (args.failFast) {
			opts.continueOnError = false
		}
		let res = await client.stackAnalysisBatch(workspaceRoot, html, opts)
		const batchAnalysis =
			res && typeof res === 'object' && res != null && 'analysis' in res ? res.analysis : res
		if (summary && !html && typeof batchAnalysis === 'object') {
			const summaries = {}
			for (const [purl, report] of Object.entries(batchAnalysis)) {
				if (report?.providers) {
					for (const provider of Object.keys(report.providers)) {
						const sources = report.providers[provider]?.sources
						if (sources) {
							for (const [source, data] of Object.entries(sources)) {
								if (data?.summary) {
									if (!summaries[purl]) {
										summaries[purl] = {}
									}
									if (!summaries[purl][provider]) {
										summaries[purl][provider] = {}
									}
									summaries[purl][provider][source] = data.summary
								}
							}
						}
					}
				}
			}
			if (res && typeof res === 'object' && res != null && 'metadata' in res) {
				res = { analysis: summaries, metadata: res.metadata }
			} else {
				res = summaries
			}
		}
		if (html) {
			const htmlContent = res && typeof res === 'object' && 'analysis' in res ? res.analysis : res
			console.log(htmlContent)
		} else {
			console.log(JSON.stringify(res, null, 2))
		}
	}
}

// command for license checking
const license = {
	command: 'license </path/to/manifest>',
	desc: 'Display project license information from manifest and LICENSE file in JSON format',
	builder: yargs => yargs.positional(
		'/path/to/manifest',
		{
			desc: 'manifest path for license analysis',
			type: 'string',
			normalize: true,
		}
	),
	handler: async args => {
		let manifestPath = args['/path/to/manifest']

		const opts = {} // CLI options can be extended in the future
		try {
			selectTrustifyDABackend(opts)
		} catch (err) {
			console.error(JSON.stringify({ error: err.message }, null, 2))
			process.exit(1)
		}

		let localResult
		try {
			localResult = getProjectLicense(manifestPath)
		} catch (err) {
			console.error(JSON.stringify({ error: `Failed to read manifest: ${err.message}` }, null, 2))
			process.exit(1)
		}

		const errors = []

		// Build LicenseInfo objects
		const buildLicenseInfo = async (spdxId) => {
			if (!spdxId) {return null}

			const licenseInfo = { spdxId }

			try {
				const details = await getLicenseDetails(spdxId, opts)
				if (details) {
					// Check if backend recognized the license as valid
					if (details.category === 'UNKNOWN') {
						errors.push(`"${spdxId}" is not a valid SPDX license identifier. Please use a valid SPDX expression (e.g., "Apache-2.0", "MIT"). See https://spdx.org/licenses/`)
					} else {
						Object.assign(licenseInfo, details)
					}
				} else {
					errors.push(`No license details found for ${spdxId}`)
				}
			} catch (err) {
				errors.push(`Failed to fetch details for ${spdxId}: ${err.message}`)
			}

			return licenseInfo
		}

		const output = {
			manifestLicense: await buildLicenseInfo(localResult.fromManifest),
			fileLicense: await buildLicenseInfo(localResult.fromFile),
			mismatch: localResult.mismatch
		}

		if (errors.length > 0) {
			output.errors = errors
		}

		console.log(JSON.stringify(output, null, 2))
	}
}

const sbom = {
	command: 'sbom </path/to/manifest> [--output]',
	desc: 'generate a CycloneDX SBOM from a manifest file',
	builder: yargs => yargs.positional(
		'/path/to/manifest',
		{
			desc: 'manifest path for SBOM generation',
			type: 'string',
			normalize: true,
		}
	).options({
		output: {
			alias: 'o',
			desc: 'Write SBOM JSON to a file instead of stdout',
			type: 'string',
			normalize: true,
		},
		workspaceDir: {
			alias: 'w',
			desc: 'Workspace root directory (for monorepos; lock file is expected here)',
			type: 'string',
			normalize: true,
		}
	}),
	handler: async args => {
		let manifest = args['/path/to/manifest']
		const opts = args.workspaceDir ? { TRUSTIFY_DA_WORKSPACE_DIR: args.workspaceDir } : {}
		let result
		try {
			result = await generateSbom(manifest, opts)
		} catch (err) {
			console.error(JSON.stringify({ error: `Failed to generate SBOM: ${err.message}` }, null, 2))
			process.exit(1)
		}
		const json = JSON.stringify(result, null, 2)
		if (args.output) {
			try {
				fs.writeFileSync(args.output, json)
			} catch (err) {
				console.error(JSON.stringify({ error: `Failed to write output file: ${err.message}` }, null, 2))
				process.exit(1)
			}
		} else {
			console.log(json)
		}
	}
}

// parse and invoke the command
yargs(hideBin(process.argv))
	.usage(`Usage: ${process.argv[0].includes("node") ?  path.parse(process.argv[1]).base : path.parse(process.argv[0]).base} {component|stack|stack-batch|image|validate-token|license|sbom}`)
	.command(stack)
	.command(stackBatch)
	.command(component)
	.command(image)
	.command(validateToken)
	.command(license)
	.command(sbom)
	.scriptName('')
	.version(false)
	.demandCommand(1)
	.wrap(null)
	.parse()
