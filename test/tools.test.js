import { expect } from 'chai'
import esmock from 'esmock'
import { afterEach } from 'mocha'

import { getCustom, getCustomPath} from "../src/tools.js"


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
