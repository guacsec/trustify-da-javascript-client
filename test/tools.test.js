import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import { expect } from 'chai'
import esmock from 'esmock'
import { afterEach } from 'mocha'

import { getCustom, getCustomPath, invokeCommand } from "../src/tools.js"


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

		test('when exists as environment variable and opts, return opts value', () => {
			process.env['DUMMY_KEY'] = 'dummy-env-value'
			let opts = { 'DUMMY_KEY': 'dummy-opts-value' }
			let fetchedValue = getCustom('DUMMY_KEY', 'dummy-default-value', opts)
			expect(fetchedValue).to.equal('dummy-opts-value')
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

		test('when exists as environment variable and opts, return opts value', () => {
			process.env['TRUSTIFY_DA_DUMMY_PATH'] = 'dummy-env-value'
			let opts = { 'TRUSTIFY_DA_DUMMY_PATH': 'dummy-opts-value' }
			let fetchedValue = getCustomPath('dummy', opts)
			expect(fetchedValue).to.equal('dummy-opts-value')
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

suite('invokeCommand', function () {
	this.timeout(10000)
	const windowsTest = process.platform === 'win32' ? test : test.skip
	let directory

	suiteSetup(() => {
		directory = fs.mkdtempSync(path.join(os.tmpdir(), 'trustify-da tools &-'))
	})

	suiteTeardown(() => fs.rmSync(directory, { recursive: true, force: true }))

	/** Catches shell interpretation/pre-quoting of native paths and dropped cwd/stdin options. */
	test('passes literal arguments to native executables in paths with spaces and ampersands', () => {
		const bin = path.join(directory, path.basename(process.execPath))
		fs.copyFileSync(process.execPath, bin)
		const args = ['a&b', 'two words', '', 'a"b', '%PATH%', '!value!', 'tail\\']
		const script = 'process.stdout.write(JSON.stringify({args:process.argv.slice(1),cwd:process.cwd(),input:require("node:fs").readFileSync(0,"utf8")}))'
		const result = JSON.parse(invokeCommand(bin, ['-e', script, '--', ...args], {
			cwd: directory, input: 'stdin content'
		}))
		expect(result).to.deep.equal({ args, cwd: fs.realpathSync(directory), input: 'stdin content' })
	})

	/** Catches reverting our output buffer to spawnSync's 1 MiB default. */
	test('captures dependency-tree output larger than 1 MiB', () => {
		const result = invokeCommand(process.execPath, ['-e', 'process.stdout.write("x".repeat(2 * 1024 * 1024))'])
		expect(result).to.equal('x'.repeat(2 * 1024 * 1024))
	})

	/** Catches returning stdout instead of throwing when a tool exits unsuccessfully. */
	test('throws nonzero exits with captured output and status', () => {
		const run = () => invokeCommand(process.execPath, ['-e',
			'require("node:fs").writeSync(1,"partial output");require("node:fs").writeSync(2,"tool failed");process.exit(7)'])
		expect(run).to.throw(Error, 'tool failed').that.includes({
			status: 7, stdout: 'partial output', stderr: 'tool failed'
		})
	})

	/** Catches losing the error code used by providers to detect unavailable tools. */
	test('throws ENOENT for an unavailable tool', () => {
		expect(() => invokeCommand('trustify-da-command-that-does-not-exist', []))
			.to.throw().with.property('code', 'ENOENT')
	})

	/** Catches treating a killed process with null status as successful. */
	test('throws when a tool times out', () => {
		expect(() => invokeCommand(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { timeout: 100 }))
			.to.throw().with.property('code', 'ETIMEDOUT')
	})

	/** Exercises real cmd.exe wrapper execution, not a reconstruction of its escaped command string. */
	windowsTest('runs Maven/Gradle-style batch wrappers', () => {
		for (const name of ['mvnw.cmd', 'gradlew.bat']) {
			const wrapper = path.join(directory, name)
			fs.writeFileSync(wrapper, '@echo off\r\necho %1\r\n')
			expect(invokeCommand(wrapper, ['project path & data'], { cwd: directory }).trim())
				.to.equal('"project path & data"')
		}
	})

	/** Exercises npm shim reparsing and PATHEXT lookup for both explicit and extensionless names. */
	windowsTest('runs npm .bin shims with literal arguments', () => {
		const shimDirectory = path.join(directory, 'node_modules', '.bin')
		fs.mkdirSync(shimDirectory, { recursive: true })
		const script = path.join(directory, 'argv.cjs')
		fs.writeFileSync(script, 'process.stdout.write(JSON.stringify(process.argv.slice(2)))')
		const shim = path.join(shimDirectory, 'argv.cmd')
		fs.writeFileSync(shim, `@echo off\r\n"${process.execPath}" "${script}" %*\r\n`)
		const args = ['project path & data', '"(foo|bar>baz)"', '', '%PATH%', '!value!']
		const originalPath = process.env.PATH
		try {
			process.env.PATH = `${shimDirectory}${path.delimiter}${originalPath}`
			for (const command of ['argv', 'argv.cmd']) {
				expect(JSON.parse(invokeCommand(command, args, { cwd: directory }))).to.deep.equal(args)
			}
		} finally {
			process.env.PATH = originalPath
		}
	})
})
