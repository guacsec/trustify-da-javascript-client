import { expect } from 'chai'

import { resolveBatchMetadata, resolveContinueOnError } from '../src/batch_opts.js'

suite('resolveContinueOnError', () => {
	test('defaults to true', () => {
		expect(resolveContinueOnError({})).to.be.true
	})

	test('opts false disables', () => {
		expect(resolveContinueOnError({ continueOnError: false })).to.be.false
	})

	test('env false disables', () => {
		const prev = process.env.TRUSTIFY_DA_CONTINUE_ON_ERROR
		process.env.TRUSTIFY_DA_CONTINUE_ON_ERROR = 'false'
		try {
			expect(resolveContinueOnError({})).to.be.false
		} finally {
			if (prev === undefined) {
				delete process.env.TRUSTIFY_DA_CONTINUE_ON_ERROR
			} else {
				process.env.TRUSTIFY_DA_CONTINUE_ON_ERROR = prev
			}
		}
	})
})

suite('resolveBatchMetadata', () => {
	test('defaults to false', () => {
		expect(resolveBatchMetadata({})).to.be.false
	})

	test('opts true enables', () => {
		expect(resolveBatchMetadata({ batchMetadata: true })).to.be.true
	})

	test('env true enables', () => {
		const prev = process.env.TRUSTIFY_DA_BATCH_METADATA
		process.env.TRUSTIFY_DA_BATCH_METADATA = 'true'
		try {
			expect(resolveBatchMetadata({})).to.be.true
		} finally {
			if (prev === undefined) {
				delete process.env.TRUSTIFY_DA_BATCH_METADATA
			} else {
				process.env.TRUSTIFY_DA_BATCH_METADATA = prev
			}
		}
	})
})
