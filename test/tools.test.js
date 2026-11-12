import { expect } from 'chai'
import esmock from 'esmock'
import { afterEach } from 'mocha'
import { createSandbox } from 'sinon'

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

/** Runs the real command boundary with a simulated host and intercepted subprocess/filesystem. */
async function interceptCommand(platform, run, files = []) {
	const invocations = []
	const tools = await esmock('../src/tools.js', {
		child_process: {
			execFileSync: (bin, args, opts) => {
				invocations.push({ bin, args, opts })
				return 'command output'
			}
		},
		'node:fs': {
			statSync: file => files.includes(file) ? { isFile: () => true } : undefined
		}
	})
	const sandbox = createSandbox()
	sandbox.stub(process, 'platform').value(platform)
	sandbox.stub(process, 'env').value({
		...process.env,
		PATH: 'C:\\Tools',
		PATHEXT: '.COM;.EXE;.BAT;.CMD',
		ComSpec: 'C:\\Windows\\System32\\cmd.exe'
	})
	try {
		await run(tools, invocations)
	} finally {
		sandbox.restore()
	}
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

	suite('invokeCommand subprocess boundary', () => {
		for (const tempDir of ['D:\\Temp', 'D:\\Temp Folder', 'D:\\Temp&Untrusted']) {
			/** Verifies venv targets and interpreters reach native execution as literal, complete paths. */
			test(`keeps native Windows paths literal under ${tempDir}`, async () => {
				await interceptCommand('win32', (tools, invocations) => {
					// Given a target and interpreter on a different drive from the working directory
					const target = `${tempDir}\\trustify_da_env_js`
					const interpreter = `${target}\\Scripts\\python.exe`
					const opts = { cwd: 'C:\\workspace', timeout: 5000 }
					// When creating the venv and upgrading pip
					tools.invokeCommand('python.exe', ['-m', 'venv', target], opts)
					const result = tools.invokeCommand(interpreter, ['-m', 'pip', 'install', '--upgrade', 'pip'], opts)
					// Then neither call exposes the paths to a shell or pre-quotes the native arguments
					expect(invocations.map(({ bin, args, opts }) => ({ bin, args, shell: opts.shell })))
						.to.deep.equal([
							{ bin: 'python.exe', args: ['-m', 'venv', target], shell: false },
							{ bin: interpreter, args: ['-m', 'pip', 'install', '--upgrade', 'pip'], shell: false }
						])
					expect(invocations[1].opts).to.include({ cwd: 'C:\\workspace', timeout: 5000, maxBuffer: 10 * 1024 * 1024 })
					expect(opts).to.deep.equal({ cwd: 'C:\\workspace', timeout: 5000 })
					expect(result).to.equal('command output')
				})
			})
		}

		for (const extension of ['exe', 'com']) {
			/** Verifies caller options cannot accidentally restore shell interpretation of native paths. */
			test(`disables shell and verbatim argument options for Windows .${extension}`, async () => {
				await interceptCommand('win32', (tools, invocations) => {
					// Given shell and verbatim options that would bypass native argument protection
					const bin = `D:\\Tools & More\\python.${extension}`
					// When invoking a native executable
					tools.invokeCommand(bin, ['%TEMP%', '!value!', 'a"b', 'a&b'], { shell: true, windowsVerbatimArguments: true })
					// Then Node retains responsibility for quoting individual native arguments
					expect(invocations[0]).to.include({ bin })
					expect(invocations[0].args).to.deep.equal(['%TEMP%', '!value!', 'a"b', 'a&b'])
					expect(invocations[0].opts).to.include({ shell: false, windowsVerbatimArguments: false })
				})
			})
		}

		for (const extension of ['bat', 'CMD']) {
			/** Verifies batch wrappers receive cmd-escaped command and argument tokens, including expansion syntax. */
			test(`escapes Windows .${extension} wrapper inputs`, async () => {
				await interceptCommand('win32', (tools, invocations) => {
					// Given a configured wrapper and data containing cmd metacharacters
					const bin = `D:\\Tools & More\\wrapper.${extension}`
					// When invoking the wrapper (never executed by this test)
					tools.invokeCommand(bin, ['D:\\Temp&Untrusted', '%TEMP%', '!value!', 'a"b', 'tail\\', ''])
					// Then cmd autorun/delayed expansion are disabled and all tokens are escaped
					expect(invocations[0].bin).to.equal('C:\\Windows\\System32\\cmd.exe')
					expect(invocations[0].args).to.deep.equal([
						'/d', '/v:off', '/s', '/c',
						`"D:\\Tools^ ^&^ More\\wrapper.${extension} ^"D:\\Temp^&Untrusted^" ^"^%TEMP^%^" ^"^!value^!^" ^"a\\^"b^" ^"tail\\\\^" ^"^""`
					])
					expect(invocations[0].opts).to.include({ shell: false, windowsVerbatimArguments: true })
				})
			})
		}

		for (const [name, file, expectedBin, expectedArgs] of [
			['python', 'C:\\Tools\\python.EXE', 'C:\\Tools\\python.EXE', ['--version']],
			['npm', 'C:\\Tools\\npm.CMD', 'C:\\Windows\\System32\\cmd.exe', ['/d', '/v:off', '/s', '/c', '"C:\\Tools\\npm.CMD ^"--version^""']],
			['D:\\project\\node_modules\\.bin\\npm', 'D:\\project\\node_modules\\.bin\\npm.CMD', 'C:\\Windows\\System32\\cmd.exe', ['/d', '/v:off', '/s', '/c', '"D:\\project\\node_modules\\.bin\\npm.CMD ^^^"--version^^^""']]
		]) {
			/** Verifies extensionless native commands and batch shims retain Windows command lookup support. */
			test(`resolves Windows command ${name}`, async () => {
				await interceptCommand('win32', (tools, invocations) => {
					// When resolving an extensionless command through PATH/PATHEXT
					tools.invokeCommand(name, ['--version'], { cwd: 'C:\\workspace' })
					// Then the selected file determines native versus escaped batch invocation
					expect(invocations[0].bin).to.equal(expectedBin)
					expect(invocations[0].args).to.deep.equal(expectedArgs)
					expect(invocations[0].opts.shell).to.equal(false)
				}, [file])
			})
		}

		/** Verifies explicit .cmd names get the same shim reparse protection as extensionless names. */
		test('resolves PATH shims before escaping explicit .cmd commands', async () => {
			const shim = 'D:\\project\\node_modules\\.bin\\npm.cmd'
			await interceptCommand('win32', (tools, invocations) => {
				// Given both names resolve to the same shim, with an exact-extension decoy present
				process.env.PATH = 'D:\\project\\node_modules\\.bin'
				process.env.PATHEXT = '.exe;.cmd'
				const args = ['D:\\Temp&Untrusted', 'a"&b', '%TEMP%', '!value!']
				// When invoking both the extensionless and explicit-extension names
				tools.invokeCommand('npm', args)
				tools.invokeCommand('npm.cmd', args)
				// Then the shim arguments survive both parsing passes, without selecting npm.cmd.exe
				const expectedArgs = ['/d', '/v:off', '/s', '/c',
					'"D:\\project\\node_modules\\.bin\\npm.cmd ^^^"D:\\Temp^^^&Untrusted^^^" ^^^"a\\^^^"^^^&b^^^" ^^^"^^^%TEMP^^^%^^^" ^^^"^^^!value^^^!^^^""']
				expect(invocations.map(({ bin, args }) => ({ bin, args }))).to.deep.equal([
					{ bin: 'C:\\Windows\\System32\\cmd.exe', args: expectedArgs },
					{ bin: 'C:\\Windows\\System32\\cmd.exe', args: expectedArgs }
				])
			}, [shim, `${shim}.exe`])
		})

		/** Verifies batch arguments cannot introduce command lines that caret escaping does not protect. */
		test('rejects line breaks before invoking a Windows wrapper', async () => {
			await interceptCommand('win32', (tools, invocations) => {
				for (const value of ['safe\ncommand', 'safe\rcommand']) {
					expect(() => tools.invokeCommand('mvn.cmd', [value])).to.throw('line breaks')
				}
				expect(invocations).to.deep.equal([])
			})
		})

		/** Verifies POSIX command inputs and explicit caller options pass through unchanged. */
		test('preserves non-Windows invocation behavior', async () => {
			await interceptCommand('linux', (tools, invocations) => {
				// Given POSIX paths and literal arguments
				const bin = '/tools with spaces/python'
				const args = ['-m', 'venv', '/tmp/a&b', '$HOME']
				// When invoking the non-Windows command
				tools.invokeCommand(bin, args, { cwd: '/workspace', shell: false })
				// Then no Windows resolution, quoting or shell flags are introduced
				expect(invocations[0].bin).to.equal(bin)
				expect(invocations[0].args).to.deep.equal(args)
				expect(invocations[0].opts).to.include({ cwd: '/workspace', shell: false })
				expect(invocations[0].opts).not.to.have.property('windowsVerbatimArguments')
			})
		})
	})


})
