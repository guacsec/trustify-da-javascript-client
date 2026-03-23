import { getCustom } from './tools.js'

/**
 * Whether to skip failed manifests and continue (default), or fail on first SBOM/validation error.
 * `opts.continueOnError` overrides; env `TRUSTIFY_DA_CONTINUE_ON_ERROR=false` disables continuation.
 *
 * @param {{ continueOnError?: boolean, TRUSTIFY_DA_CONTINUE_ON_ERROR?: string, [key: string]: unknown }} [opts={}]
 * @returns {boolean} true = collect errors (default), false = fail-fast
 */
export function resolveContinueOnError(opts = {}) {
	if (typeof opts.continueOnError === 'boolean') {
		return opts.continueOnError
	}
	const v = getCustom('TRUSTIFY_DA_CONTINUE_ON_ERROR', null, opts)
	if (v != null && String(v).trim() !== '') {
		return String(v).toLowerCase() !== 'false'
	}
	return true
}

/**
 * When true, `stackAnalysisBatch` returns `{ analysis, metadata }` instead of the backend response only.
 * `opts.batchMetadata` overrides; env `TRUSTIFY_DA_BATCH_METADATA=true` enables.
 *
 * @param {{ batchMetadata?: boolean, TRUSTIFY_DA_BATCH_METADATA?: string, [key: string]: unknown }} [opts={}]
 * @returns {boolean}
 */
export function resolveBatchMetadata(opts = {}) {
	if (typeof opts.batchMetadata === 'boolean') {
		return opts.batchMetadata
	}
	const v = getCustom('TRUSTIFY_DA_BATCH_METADATA', null, opts)
	if (v != null && String(v).trim() !== '') {
		return String(v).toLowerCase() === 'true'
	}
	return false
}
