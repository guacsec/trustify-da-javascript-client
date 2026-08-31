import { expect } from 'chai'
import esmock from 'esmock'
import { afterEach } from 'mocha'

import { getCustom, getCustomPath } from "../src/tools.js"


/**
 *
 * @param {string}operatingSystem
 * @return {Promise<*>}
 */
async function mockToolsPartial(operatingSystem) {
	return await esmock('../src/tools.js', {
		os: {
			platform: () => operatingSystem
		}
	}
	)
}

suite('testing the various tools and utility functions', () => {
	suite('test the getCustom utility function', () => {
		afterEach(() => delete process.env['DUMMY_KEY'])

		test('when exists as environment variable and opts, return environment variables value', () => {
			process.env['DUMMY_KEY'] = 'dummy-env-value'
			let opts = { 'DUMMY_KEY': 'dummy-opts-value' }
			let fetchedValue = getCustom('DUMMY_KEY', 'dummy-default-value', opts)
			expect(fetchedValue).to.equal('dummy-env-value')
		})

		test('when no environment variable but exists as opts, return opts value', () => {
			let opts = { 'DUMMY_KEY': 'dummy-opts-value' }
			let fetchedValue = getCustom('DUMMY_KEY', 'dummy-default-value', opts)
			expect(fetchedValue).to.equal('dummy-opts-value')
		})

		test('when no environment variable and no opts, return default value', () => {
			let fetchedValue = getCustom('DUMMY_KEY', 'dummy-default-value')
			expect(fetchedValue).to.equal('dummy-default-value')
		})
	})

	suite('test the getCustomPath utility function', () => {
		afterEach(() => delete process.env['TRUSTIFY_DA_DUMMY_PATH'])

		test('when exists as environment variable and opts, return environment variables value', () => {
			process.env['TRUSTIFY_DA_DUMMY_PATH'] = 'dummy-env-value'
			let opts = { 'TRUSTIFY_DA_DUMMY_PATH': 'dummy-opts-value' }
			let fetchedValue = getCustomPath('dummy', opts)
			expect(fetchedValue).to.equal('dummy-env-value')
		})

		test('when no environment variable but exists as opts, return opts value', () => {
			let opts = { 'TRUSTIFY_DA_DUMMY_PATH': 'dummy-opts-value' }
			let fetchedValue = getCustomPath('dummy', opts)
			expect(fetchedValue).to.equal('dummy-opts-value')
		})

		test('when no environment variable and no opts, return default value', () => {
			let fetchedValue = getCustomPath('dummy')
			expect(fetchedValue).to.equal('dummy')
		})

	})

	suite('test getCustomPath executable path validation', () => {
		afterEach(() => delete process.env['TRUSTIFY_DA_DUMMY_PATH'])

		/** Verifies that bare command names pass validation (resolved via OS PATH lookup). */
		test('allows bare command names without path separators', () => {
			const commands = ['mvn', 'npm', 'go', 'cargo', 'pip3']
			const saved = {}
			for (const cmd of commands) {
				const envKey = `TRUSTIFY_DA_${cmd.toUpperCase()}_PATH`
				if (envKey in process.env) {
					saved[envKey] = process.env[envKey]
					delete process.env[envKey]
				}
			}
			try {
				for (const cmd of commands) {
					expect(getCustomPath(cmd)).to.equal(cmd)
				}
			} finally {
				for (const [key, val] of Object.entries(saved)) {
					process.env[key] = val
				}
			}
		})

		/** Verifies that valid absolute paths are accepted. */
		test('allows valid absolute paths', () => {
			process.env['TRUSTIFY_DA_DUMMY_PATH'] = '/usr/bin/mvn'
			expect(getCustomPath('dummy')).to.equal('/usr/bin/mvn')

			process.env['TRUSTIFY_DA_DUMMY_PATH'] = '/usr/local/bin/npm'
			expect(getCustomPath('dummy')).to.equal('/usr/local/bin/npm')
		})

		/** Reproducer: relative path with traversal segments must be rejected. */
		test('rejects relative paths containing ".." traversal segments', () => {
			process.env['TRUSTIFY_DA_DUMMY_PATH'] = '../../etc/malicious'
			expect(() => getCustomPath('dummy')).to.throw(
				Error, 'path contains directory traversal segment (..)'
			)
		})

		/** Verifies that absolute paths with embedded traversal segments are rejected. */
		test('rejects absolute paths containing ".." traversal segments', () => {
			process.env['TRUSTIFY_DA_DUMMY_PATH'] = '/usr/bin/../../../tmp/evil'
			expect(() => getCustomPath('dummy')).to.throw(
				Error, 'path contains directory traversal segment (..)'
			)
		})

		/** Verifies that paths starting with "./" (workspace-relative) are rejected. */
		test('rejects paths starting with "./"', () => {
			process.env['TRUSTIFY_DA_DUMMY_PATH'] = './malicious.sh'
			expect(() => getCustomPath('dummy')).to.throw(
				Error, "relative paths starting with './' are not allowed"
			)
		})

		/** Verifies that traversal paths supplied via opts are also rejected. */
		test('rejects traversal paths provided via opts', () => {
			const opts = { 'TRUSTIFY_DA_DUMMY_PATH': '../../tmp/evil' }
			expect(() => getCustomPath('dummy', opts)).to.throw(
				Error, 'path contains directory traversal segment (..)'
			)
		})

		/** Verifies that a bare '..' without path separators is rejected. */
		test('rejects bare ".." without path separators', () => {
			process.env['TRUSTIFY_DA_DUMMY_PATH'] = '..'
			expect(() => getCustomPath('dummy')).to.throw(
				Error, 'path contains directory traversal segment (..)'
			)
		})

		/** Verifies that relative paths with separators (e.g. subdir/binary) are rejected. */
		test('rejects relative paths with separators', () => {
			process.env['TRUSTIFY_DA_DUMMY_PATH'] = 'subdir/binary'
			expect(() => getCustomPath('dummy')).to.throw(
				Error, 'relative paths are not allowed, use an absolute path or a bare command name'
			)
		})

		/** Verifies that rejected paths include the offending path in the error message. */
		test('error message includes the rejected path', () => {
			process.env['TRUSTIFY_DA_DUMMY_PATH'] = '../../sneaky/script'
			expect(() => getCustomPath('dummy')).to.throw('../../sneaky/script')
		})
	})

	suite('test resolveBinary wrapper path regression', () => {
		/** Verifies that resolveBinary with a wrapper path bypasses getCustomPath validation. */
		test('wrapper path from traverseForWrapper is not subject to path validation', async () => {
			// Given: a mocked traverseForWrapper that returns a workspace-relative wrapper path
			const tools = await esmock('../src/tools.js', {}, {
				'node:fs': {
					accessSync: () => undefined
				}
			})

			// When: resolveBinary finds a wrapper, it returns it directly without validation
			const result = tools.resolveBinary('mvn', 'mvnw', '/workspace/project')
			expect(result).to.equal('/workspace/project/mvnw')
		})
	})

	suite('test the handleSpacesInPath utility function', () => {

		test('Windows Path with spaces', async () => {
			const tools = await mockToolsPartial("win32")
			let path = "c:\\users\\john doe\\pom.xml"
			let expectedPath = "\"c:\\users\\john doe\\pom.xml\""
			let actualPath = tools.handleSpacesInPath(path)
			expect(actualPath).to.equal(expectedPath)
		})

		test('Windows Path with no spaces', async () => {
			const tools = await mockToolsPartial("win32")
			let path = "c:\\users\\john\\pom.xml"
			let expectedPath = "c:\\users\\john\\pom.xml"
			let actualPath = tools.handleSpacesInPath(path)
			expect(actualPath).to.equal(expectedPath)
		})

	})


})
