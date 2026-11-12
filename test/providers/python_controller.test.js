import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import { expect } from 'chai'
import esmock from 'esmock'

import Python_controller from '../../src/providers/python_controller.js'
import {
	getParser,
	getRequirementQuery,
	readRequirementsFile
} from '../../src/providers/requirements_parser.js'

const REQUIREMENTS_MANIFEST = 'test/providers/tst_manifests/pip/pip_requirements_txt_no_ignore/requirements.txt'

/**
 * Loads Python_controller with os.platform() and command invocation stubbed, then
 * constructs a virtual-environment controller so the venv setup invocations can be
 * inspected. Stubbing the parser keeps the test independent of the tree-sitter wasm
 * artifacts.
 * @param {string} platform - platform reported by os.platform()
 * @param {string} sourcePython - configured source python binary
 * @return {Promise<{controller: Python_controller, invocations: Array<{bin: string, args: string[]}>}>}
 */
async function constructVirtualEnvController(platform, sourcePython) {
	const invocations = []
	/** Records a command invocation instead of executing it. */
	const recordInvocation = (bin, args) => {
		invocations.push({ bin, args })
		return ''
	}
	const { default: MockedPythonController } = await esmock('../../src/providers/python_controller.js', {
		os: { default: { platform: () => platform }, EOL: '\n' },
		'../../src/tools.js': {
			environmentVariableIsPopulated: () => false,
			getCustom: () => undefined,
			invokeCommand: recordInvocation
		},
		'../../src/providers/requirements_parser.js': {
			getParser: async () => null,
			getRequirementQuery: async () => null,
			getPinnedVersionQuery: async () => null
		}
	})
	const controller = new MockedPythonController(false, 'pip3', sourcePython, REQUIREMENTS_MANIFEST)
	return { controller, invocations }
}

suite('Python_controller BEST_EFFORTS validation', function() {
	let originalBestEfforts

	suiteSetup(function() {
		originalBestEfforts = process.env['TRUSTIFY_DA_PYTHON_INSTALL_BEST_EFFORTS']
	})

	suiteTeardown(function() {
		if (originalBestEfforts === undefined) {
			delete process.env['TRUSTIFY_DA_PYTHON_INSTALL_BEST_EFFORTS']
		} else {
			process.env['TRUSTIFY_DA_PYTHON_INSTALL_BEST_EFFORTS'] = originalBestEfforts
		}
	})

	/** Verifies that BEST_EFFORTS=true without VIRTUAL_ENV=true throws a descriptive error. */
	test('throws when BEST_EFFORTS=true is set without VIRTUAL_ENV=true (realEnvironment=true)', async function() {
		// Given a controller in real environment mode (VIRTUAL_ENV not set)
		process.env['TRUSTIFY_DA_PYTHON_INSTALL_BEST_EFFORTS'] = 'true'
		let controller = new Python_controller(true, 'pip3', 'python3', 'test/providers/tst_manifests/pip/pip_requirements_txt_no_ignore/requirements.txt')

		// When getDependencies is called
		try {
			await controller.getDependencies(false)
			expect.fail('Expected getDependencies to throw')
		} catch (error) {
			// Then the error message names both environment variables
			expect(error.message).to.include('TRUSTIFY_DA_PYTHON_INSTALL_BEST_EFFORTS')
			expect(error.message).to.include('TRUSTIFY_DA_PYTHON_VIRTUAL_ENV')
		}
	})

	/** Verifies that the validation does not trigger when BEST_EFFORTS is false (default). */
	test('does not throw when BEST_EFFORTS is false (default)', async function() {
		// Given a controller in real environment mode with default BEST_EFFORTS
		delete process.env['TRUSTIFY_DA_PYTHON_INSTALL_BEST_EFFORTS']
		let controller = new Python_controller(true, 'pip3', 'python3', 'test/providers/tst_manifests/pip/pip_requirements_txt_no_ignore/requirements.txt')

		// When getDependencies is called, then no BEST_EFFORTS validation error is thrown
		// (it may throw for other reasons like missing pip, which is acceptable)
		try {
			await controller.getDependencies(false)
		} catch (error) {
			expect(error.message).to.not.include('TRUSTIFY_DA_PYTHON_INSTALL_BEST_EFFORTS')
		}
	})

	/** Verifies that BEST_EFFORTS=true with VIRTUAL_ENV=true does not trigger the validation. */
	test('does not throw the validation error when both BEST_EFFORTS=true and VIRTUAL_ENV=true (realEnvironment=false)', async function() {
		this.timeout(120000)
		// Given a controller in virtual environment mode (VIRTUAL_ENV=true)
		process.env['TRUSTIFY_DA_PYTHON_INSTALL_BEST_EFFORTS'] = 'true'
		let controller
		try {
			controller = new Python_controller(false, 'pip3', 'python3', 'test/providers/tst_manifests/pip/pip_requirements_txt_no_ignore/requirements.txt')
		} catch (error) {
			this.skip()
			return
		}

		// When getDependencies is called, then the BEST_EFFORTS+VIRTUAL_ENV validation does not trigger
		// (it may throw for other reasons like venv setup or MATCH_MANIFEST_VERSIONS conflict, which is acceptable)
		try {
			await controller.getDependencies(false)
		} catch (error) {
			expect(error.message).to.not.include('requires TRUSTIFY_DA_PYTHON_VIRTUAL_ENV')
		}
	})
})

suite('Python_controller virtual environment executables', function() {
	// Windows venv executable names must not depend on how the source interpreter is named (TC-7485).
	for (const sourcePython of ['python3', 'python']) {
		/** Verifies that a Windows venv created from `sourcePython` upgrades pip via Scripts/python.exe. */
		test(`upgrades pip via Scripts/python.exe on Windows for a ${sourcePython} source`, async function() {
			// Given a Windows host and a configured source interpreter named sourcePython
			const { controller, invocations } = await constructVirtualEnvController('win32', sourcePython)

			// When the venv is prepared while the controller is constructed
			const venvInvocation = invocations[0]
			const pipUpgradeInvocation = invocations[1]

			// Then the venv is created from the configured source interpreter
			expect(invocations).to.have.lengthOf(2)
			expect(venvInvocation.bin).to.equal(sourcePython)
			expect(venvInvocation.args).to.deep.equal(['-m', 'venv', path.join(path.sep, 'tmp', 'trustify_da_env_js')])

			// Then the executable paths are anchored to the venv directory that was created.
			// Resolving the recorded target makes this match the controller's drive-prefixed
			// Windows paths on a native host as well as under the mocked win32 platform.
			const expectedVenvDir = path.resolve(venvInvocation.args[2])
			expect(path.resolve(controller.pythonEnvDir)).to.equal(expectedVenvDir)
			const expectedPythonBin = path.join(expectedVenvDir, 'Scripts', 'python.exe')
			const expectedPipBin = path.join(expectedVenvDir, 'Scripts', 'pip.exe')

			// Then the pip upgrade runs through that venv's Scripts/python.exe exactly
			expect(pipUpgradeInvocation.args).to.deep.equal(['-m', 'pip', 'install', '--upgrade', 'pip'])
			expect(pipUpgradeInvocation.bin).to.equal(expectedPythonBin)
			expect(controller.pathToPythonBin).to.equal(expectedPythonBin)

			// Then the venv pip path is exactly that venv's Scripts/pip.exe
			expect(controller.pathToPipBin).to.equal(expectedPipBin)

			// Then no invocation targets the nonexistent Scripts/python3.exe
			expect(path.basename(pipUpgradeInvocation.bin)).to.not.equal('python3.exe')
			expect(invocations.map(invocation => path.basename(invocation.bin))).to.not.include('python3.exe')
			expect(invocations.map(invocation => path.basename(invocation.bin))).to.not.include('pip3.exe')
		})
	}

	// The venv layout is independent of the source interpreter name, so POSIX
	// environments always expose bin/python and bin/pip.
	for (const sourcePython of ['python3', 'python']) {
		/** Verifies that POSIX venvs expose bin/python and bin/pip regardless of the source interpreter name. */
		test(`uses bin/python and bin/pip on non-Windows hosts for a ${sourcePython} source`, async function() {
			// Given a POSIX host and a configured source interpreter named sourcePython
			const { controller, invocations } = await constructVirtualEnvController('linux', sourcePython)

			// When the venv is prepared while the controller is constructed
			const venvInvocation = invocations[0]
			const pipUpgradeInvocation = invocations[1]

			// Then the venv is created from the configured source interpreter
			expect(invocations).to.have.lengthOf(2)
			expect(venvInvocation.bin).to.equal(sourcePython)
			expect(venvInvocation.args[2]).to.equal(path.join(path.sep, 'tmp', 'trustify_da_env_js'))

			// Then the pip upgrade runs through the venv bin/python exactly
			expect(pipUpgradeInvocation.args).to.deep.equal(['-m', 'pip', 'install', '--upgrade', 'pip'])
			expect(pipUpgradeInvocation.bin).to.equal(path.join(venvInvocation.args[2], 'bin', 'python'))
			expect(controller.pathToPythonBin).to.equal(path.join(venvInvocation.args[2], 'bin', 'python'))

			// Then the venv pip path is bin/pip
			expect(controller.pathToPipBin).to.equal(path.join(venvInvocation.args[2], 'bin', 'pip'))
		})
	}
})
suite('Python_controller requirements file decoding', () => {
	const requirementsText = 'blinker==1.9.0\r\ncertifi==2026.10.23\r\n'
	let tempDir

	suiteSetup(() => { tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'trustify-da-decoding-')) })
	suiteTeardown(() => { fs.rmSync(tempDir, { recursive: true, force: true }) })

	/**
	 * Encode requirements text with the given encoding, prefixing a BOM where applicable.
	 * @param {string} text - requirements text to encode
	 * @param {string} encoding - one of utf8, utf8-bom, utf16le-bom, utf16be-bom
	 * @returns {Buffer} encoded manifest bytes
	 */
	function encode(text, encoding) {
		if (encoding === 'utf8-bom') {
			return Buffer.concat([Buffer.from([0xEF, 0xBB, 0xBF]), Buffer.from(text, 'utf8')])
		}
		if (encoding === 'utf16le-bom') {
			return Buffer.concat([Buffer.from([0xFF, 0xFE]), Buffer.from(text, 'utf16le')])
		}
		if (encoding === 'utf16be-bom') {
			const littleEndian = Buffer.from(text, 'utf16le')
			littleEndian.swap16()
			return Buffer.concat([Buffer.from([0xFE, 0xFF]), littleEndian])
		}
		return Buffer.from(text, 'utf8')
	}

	const encodingCases = [
		{ name: 'plain UTF-8', encoding: 'utf8' },
		{ name: 'UTF-8 with BOM', encoding: 'utf8-bom' },
		{ name: 'UTF-16LE with BOM', encoding: 'utf16le-bom' },
		{ name: 'UTF-16BE with BOM', encoding: 'utf16be-bom' }
	]
	encodingCases.forEach(testCase => {
		/** Verifies the shared reader decodes every supported BOM variant to the same plain text. */
		test(`verify requirements reader decodes ${testCase.name} manifests`, () => {
			// Given a manifest written with the given encoding
			const manifest = path.join(tempDir, `requirements-${testCase.encoding}.txt`)
			fs.writeFileSync(manifest, encode(requirementsText, testCase.encoding))

			// When the shared reader loads it
			const decoded = readRequirementsFile(manifest)

			// Then the text matches the plain manifest, without a BOM or NUL characters
			expect(decoded).to.equal(requirementsText)
			expect(decoded).to.not.include('\uFEFF')
			expect(decoded).to.not.include(String.fromCharCode(0))
		})
	})

	/** Verifies the requirements query recovers real names and pinned versions from a decoded manifest. */
	test('verify requirements query recovers real packages from a UTF-16LE manifest', async () => {
		// Given the UTF-16LE-with-BOM manifest PowerShell 5.1 writes with `pip freeze > requirements.txt`
		const manifest = path.join(tempDir, 'parsed-utf16le-bom.txt')
		fs.writeFileSync(manifest, encode(requirementsText, 'utf16le-bom'))

		// When the decoded text is parsed with the requirements query
		const parser = await getParser()
		const query = await getRequirementQuery()
		const matches = query.matches(parser.parse(readRequirementsFile(manifest)).rootNode)

		// Then the package names and pinned versions are the ones written in the manifest
		expect(matches.map(match => match.captures.find(capture => capture.name === 'name').node.text))
			.to.deep.equal(['blinker', 'certifi'])
		expect(matches.map(match => match.captures.find(capture => capture.name === 'req').node.text.trim()))
			.to.deep.equal(['blinker==1.9.0', 'certifi==2026.10.23'])
	})
})
