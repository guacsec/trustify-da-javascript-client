import { expect } from 'chai'

import { evaluateMarker } from '../../src/providers/marker_evaluator.js'

let originalPlatform

suite('PEP 508 marker evaluator', () => {
	suiteSetup(() => {
		originalPlatform = process.platform
		Object.defineProperty(process, 'platform', { value: 'linux', configurable: true })
	})
	suiteTeardown(() => {
		Object.defineProperty(process, 'platform', { value: originalPlatform, configurable: true })
	})

	suite('in operator — PEP 508 string containment', () => {
		test('substring match: sys_platform in wider string', () => {
			expect(evaluateMarker("sys_platform in 'linux2'")).to.be.true
		})

		test('exact match: sys_platform in exact string', () => {
			expect(evaluateMarker("sys_platform in 'linux'")).to.be.true
		})

		test('no match: sys_platform in unrelated string', () => {
			expect(evaluateMarker("sys_platform in 'win32'")).to.be.false
		})

		test('partial overlap but no containment', () => {
			expect(evaluateMarker("sys_platform in 'lin'")).to.be.false
		})
	})

	suite('not in operator — negated string containment', () => {
		test('substring present: sys_platform not in wider string', () => {
			expect(evaluateMarker("sys_platform not in 'linux2'")).to.be.false
		})

		test('no match: sys_platform not in unrelated string', () => {
			expect(evaluateMarker("sys_platform not in 'win32'")).to.be.true
		})

		test('partial overlap negated', () => {
			expect(evaluateMarker("sys_platform not in 'lin'")).to.be.true
		})
	})

	suite('reversed form — directional operator reversal', () => {
		test('>= is reversed to <= when operands are swapped', () => {
			expect(evaluateMarker("'3.8' >= python_version")).to.equal(
				evaluateMarker("python_version <= '3.8'")
			)
		})

		test('< is reversed to > when operands are swapped', () => {
			expect(evaluateMarker("'3.8' < python_version")).to.equal(
				evaluateMarker("python_version > '3.8'")
			)
		})

		test('> is reversed to < when operands are swapped', () => {
			expect(evaluateMarker("'3.8' > python_version")).to.equal(
				evaluateMarker("python_version < '3.8'")
			)
		})

		test('<= is reversed to >= when operands are swapped', () => {
			expect(evaluateMarker("'3.8' <= python_version")).to.equal(
				evaluateMarker("python_version >= '3.8'")
			)
		})

		test('== is unchanged when operands are swapped', () => {
			expect(evaluateMarker("'linux' == sys_platform")).to.equal(
				evaluateMarker("sys_platform == 'linux'")
			)
		})

		test('!= is unchanged when operands are swapped', () => {
			expect(evaluateMarker("'win32' != sys_platform")).to.equal(
				evaluateMarker("sys_platform != 'win32'")
			)
		})
	})
})
