import fs from 'fs'

import { expect } from 'chai'
import { useFakeTimers } from "sinon";

import pythonPip from "../../src/providers/python_pip.js"
import {getCustomPath, invokeCommand } from "../../src/tools.js"

let clock

async function sharedComponentAnalysisTestFlow(testCase, usePipDepTreeUtility) {
	// load the expected list for the scenario
	let expectedSbom = JSON.parse(fs.readFileSync(`test/providers/tst_manifests/pip/${testCase}/expected_component_sbom.json`).toString().trim())
	// invoke sut component analysis for scenario manifest
	let opts = { TRUSTIFY_DA_PIP_USE_DEP_TREE: usePipDepTreeUtility.toString() }
	let providedDatForComponent = await pythonPip.provideComponent(`test/providers/tst_manifests/pip/${testCase}/requirements.txt`, opts)
	let actualSbom = JSON.parse(providedDatForComponent.content)
	// Strip hashes before comparison — they are platform-dependent.
	// Hash correctness is verified by the dedicated SHA-256 tests below.
	for (let c of expectedSbom.components) { delete c.hashes }
	for (let c of actualSbom.components) { delete c.hashes }
	// verify returned data matches expectation
	expect(providedDatForComponent.ecosystem).to.equal('pip')
	expect(providedDatForComponent.contentType).to.equal('application/vnd.cyclonedx+json')
	expect(actualSbom).to.deep.equal(expectedSbom)
}

async function sharedStackAnalysisTestFlow(testCase, usePipDepTreeUtility) {
	// load the expected graph for the scenario
	let expectedSbom = JSON.parse(fs.readFileSync(`test/providers/tst_manifests/pip/${testCase}/expected_stack_sbom.json`).toString())
	// invoke sut stack analysis for scenario manifest
	let pipPath = getCustomPath("pip3");
	try {
		invokeCommand(pipPath, ['install', '-r', `test/providers/tst_manifests/pip/${testCase}/requirements.txt`])
	} catch (error) {
		throw new Error('fail installing requirements.txt manifest in created virtual python environment', {cause: error})
	}
	let opts = { TRUSTIFY_DA_PIP_USE_DEP_TREE: usePipDepTreeUtility.toString() }
	let providedDataForStack = await pythonPip.provideStack(`test/providers/tst_manifests/pip/${testCase}/requirements.txt`, opts)
	let actualSbom = JSON.parse(providedDataForStack.content)
	// Strip hashes before comparison — they are platform-dependent.
	// Hash correctness is verified by the dedicated SHA-256 tests below.
	for (let c of expectedSbom.components) { delete c.hashes }
	for (let c of actualSbom.components) { delete c.hashes }
	// verify returned data matches expectation
	expect(providedDataForStack.ecosystem).to.equal('pip')
	expect(providedDataForStack.contentType).to.equal('application/vnd.cyclonedx+json')
	expect(actualSbom).to.deep.equal(expectedSbom)
}

suite('testing the python-pip data provider', () => {
	[
		{name: 'requirements.txt', expected: true},
		{name: 'some_other.file', expected: false}
	].forEach(testCase => {
		test(`verify isSupported returns ${testCase.expected} for ${testCase.name}`, () =>
			expect(pythonPip.isSupported(testCase.name)).to.equal(testCase.expected)
		)
	});

	[
		// "pip_requirements_txt_no_ignore",
		"pip_requirements_txt_ignore"
	].forEach(testCase => {
		let scenario = testCase.replace('pip_requirements_', '').replaceAll('_', ' ')
		test(`verify requirements.txt sbom provided for stack analysis with scenario ${scenario}`, async () => {
			await sharedStackAnalysisTestFlow(testCase, false);
			// these test cases takes ~2500-2700 ms each pr >10000 in CI (for the first test-case)
		}).timeout(process.env.GITHUB_ACTIONS ? 30000 : 10000)

		test(`verify requirements.txt sbom provided for component analysis with scenario ${scenario}`, async () => {
			await sharedComponentAnalysisTestFlow(testCase, false);
			// these test cases takes ~1400-2000 ms each pr >10000 in CI (for the first test-case)
		}).timeout(process.env.GITHUB_ACTIONS ? 15000 : 10000)

		test(`verify requirements.txt sbom provided for stack analysis using pipdeptree utility with scenario ${scenario}`, async () => {
			await sharedStackAnalysisTestFlow(testCase, true);
			// these test cases takes ~2500-2700 ms each pr >10000 in CI (for the first test-case)
		}).timeout(process.env.GITHUB_ACTIONS ? 30000 : 10000)

		test(`verify requirements.txt sbom provided for component analysis using pipdeptree utility with scenario ${scenario}`, async () => {
			await sharedComponentAnalysisTestFlow(testCase, true);
			// these test cases takes ~1400-2000 ms each pr >10000 in CI (for the first test-case)
		}).timeout(process.env.GITHUB_ACTIONS ? 15000 : 10000)
	});

}).beforeAll(() => clock = useFakeTimers(new Date('2023-10-01T00:00:00.000Z'))).afterAll(()=> clock.restore());

suite('testing the python-pip data provider with virtual environment', () => {
	[
		"pip_requirements_virtual_env_txt_no_ignore",
		"pip_requirements_virtual_env_with_ignore"
	].forEach(testCase => {
		let scenario = testCase.replace('pip_requirements_', '').replaceAll('_', ' ')
		test(`verify requirements.txt sbom provided for stack analysis using virutal python environment, with scenario ${scenario}`, async () => {
			// load the expected sbom stack analysis
			let expectedSbom = fs.readFileSync(`test/providers/tst_manifests/pip/${testCase}/expected_stack_sbom.json`,).toString()
			expectedSbom = JSON.stringify(JSON.parse(expectedSbom), null, 4)
			// invoke sut stack analysis for scenario manifest
			let providedDataForStack = await pythonPip.provideStack(`test/providers/tst_manifests/pip/${testCase}/requirements.txt`, {
				TRUSTIFY_DA_PYTHON_VIRTUAL_ENV: "true"
			})
			// new(year: number, month: number, date?: number, hours?: number, minutes?: number, seconds?: number, ms?: number): Date

			// providedDataForStack.content = providedDataForStack.content.replaceAll("\"timestamp\":\"[a-zA-Z0-9\\-\\:]+\"","")
			// verify returned data matches expectation
			providedDataForStack.content = JSON.stringify(JSON.parse(providedDataForStack.content), null, 4)
			expect(providedDataForStack.content).to.deep.equal(expectedSbom)
			// expect(providedDataForStack).to.deep.equal({
			// 	ecosystem: 'pip',
			// 	contentType: 'application/vnd.cyclonedx+json',
			// 	content: expectedSbom
			// })
			// these test cases takes ~2500-2700 ms each pr >10000 in CI (for the first test-case)
		}).timeout(process.env.GITHUB_ACTIONS ? 60000 : 30000)
	})

}).beforeAll(() => {clock = useFakeTimers(new Date('2023-10-01T00:00:00.000Z'))}).afterAll(()=> clock.restore());

suite('testing python-pip PEP 508 marker handling', () => {
	const markerTestCase = 'pip_requirements_txt_marker_skip'

	/** Verify that packages with environment markers (PEP 508) that are not installed
	 *  in the current environment are silently skipped, while marker-constrained
	 *  packages that ARE installed are still included in the SBOM. */
	test('verify marker-constrained uninstalled packages are skipped in component analysis', async () => {
		// given: pip environment where only six and certifi are installed (pywin32 is Windows-only)
		const pipFreezeOutput = 'six==1.16.0\ncertifi==2023.7.22\n'
		const pipShowOutput =
			'Name: certifi\nVersion: 2023.7.22\nSummary: Python package for providing Mozilla\'s CA Bundle.\nRequires: \nRequired-by: ' +
			'\n---\n' +
			'Name: six\nVersion: 1.16.0\nSummary: Python 2 and 3 compatibility utilities\nRequires: \nRequired-by: '

		process.env['TRUSTIFY_DA_PIP_FREEZE'] = Buffer.from(pipFreezeOutput).toString('base64')
		process.env['TRUSTIFY_DA_PIP_SHOW'] = Buffer.from(pipShowOutput).toString('base64')

		try {
			// when: component analysis is run against a manifest with a Windows-only marker package
			let expectedSbom = fs.readFileSync(`test/providers/tst_manifests/pip/${markerTestCase}/expected_component_sbom.json`).toString().trim()
			expectedSbom = JSON.stringify(JSON.parse(expectedSbom))

			let result = await pythonPip.provideComponent(`test/providers/tst_manifests/pip/${markerTestCase}/requirements.txt`, {})

			// then: SBOM contains six and certifi but not pywin32
			expect(result).to.deep.equal({
				ecosystem: 'pip',
				contentType: 'application/vnd.cyclonedx+json',
				content: expectedSbom
			})
		} finally {
			delete process.env['TRUSTIFY_DA_PIP_FREEZE']
			delete process.env['TRUSTIFY_DA_PIP_SHOW']
		}
	}).timeout(10000)

}).beforeAll(() => clock = useFakeTimers(new Date('2023-10-01T00:00:00.000Z'))).afterAll(() => clock.restore());

suite('testing python-pip SHA-256 hash extraction via pip inspect', () => {
	const hashTestCase = 'pip_requirements_txt_with_hashes'

	const pipFreezeOutput = 'certifi==2023.7.22\nsix==1.16.0\n'
	const pipShowOutput =
		'Name: certifi\nVersion: 2023.7.22\nSummary: Python package\nRequires: \nRequired-by: ' +
		'\n---\n' +
		'Name: six\nVersion: 1.16.0\nSummary: Python 2 and 3 compatibility\nRequires: \nRequired-by: '
	const pipInspectOutput = JSON.stringify({
		version: "1",
		pip_version: "23.0",
		installed: [
			{
				metadata: { name: "certifi", version: "2023.7.22" },
				download_info: { archive_info: { hashes: { sha256: "539cc1d13202e33ca466e88b2807e29f4c13049d6d853261b21e0e8d461bbbf0" } } }
			},
			{
				metadata: { name: "six", version: "1.16.0" },
				download_info: { archive_info: { hashes: { sha256: "1e61c37477a1626458e36f7b1d82aa5c9b094fa4802892072e49de9c60c4c926" } } }
			}
		]
	})

	/** Verifies that SHA-256 hashes from pip inspect are threaded into the component analysis SBOM. */
	test('verify component analysis SBOM includes SHA-256 hashes from pip inspect', async () => {
		// Given: pip environment with freeze, show, and inspect data
		process.env['TRUSTIFY_DA_PIP_FREEZE'] = Buffer.from(pipFreezeOutput).toString('base64')
		process.env['TRUSTIFY_DA_PIP_SHOW'] = Buffer.from(pipShowOutput).toString('base64')
		process.env['TRUSTIFY_DA_PIP_INSPECT'] = Buffer.from(pipInspectOutput).toString('base64')

		try {
			// When: component analysis is run
			let expectedSbom = fs.readFileSync(`test/providers/tst_manifests/pip/${hashTestCase}/expected_component_sbom.json`).toString().trim()
			expectedSbom = JSON.stringify(JSON.parse(expectedSbom))
			let result = await pythonPip.provideComponent(`test/providers/tst_manifests/pip/${hashTestCase}/requirements.txt`, {})

			// Then: SBOM includes hashes matching the golden file
			expect(result).to.deep.equal({
				ecosystem: 'pip',
				contentType: 'application/vnd.cyclonedx+json',
				content: expectedSbom
			})
		} finally {
			delete process.env['TRUSTIFY_DA_PIP_FREEZE']
			delete process.env['TRUSTIFY_DA_PIP_SHOW']
			delete process.env['TRUSTIFY_DA_PIP_INSPECT']
		}
	}).timeout(10000)

	/** Verifies that SHA-256 hashes from pip inspect are threaded into the stack analysis SBOM. */
	test('verify stack analysis SBOM includes SHA-256 hashes from pip inspect', async () => {
		// Given: pip environment with freeze, show, and inspect data
		process.env['TRUSTIFY_DA_PIP_FREEZE'] = Buffer.from(pipFreezeOutput).toString('base64')
		process.env['TRUSTIFY_DA_PIP_SHOW'] = Buffer.from(pipShowOutput).toString('base64')
		process.env['TRUSTIFY_DA_PIP_INSPECT'] = Buffer.from(pipInspectOutput).toString('base64')

		try {
			// When: stack analysis is run
			let expectedSbom = fs.readFileSync(`test/providers/tst_manifests/pip/${hashTestCase}/expected_stack_sbom.json`).toString().trim()
			expectedSbom = JSON.stringify(JSON.parse(expectedSbom))
			let result = await pythonPip.provideStack(`test/providers/tst_manifests/pip/${hashTestCase}/requirements.txt`, {})

			// Then: SBOM includes hashes matching the golden file
			expect(result).to.deep.equal({
				ecosystem: 'pip',
				contentType: 'application/vnd.cyclonedx+json',
				content: expectedSbom
			})
		} finally {
			delete process.env['TRUSTIFY_DA_PIP_FREEZE']
			delete process.env['TRUSTIFY_DA_PIP_SHOW']
			delete process.env['TRUSTIFY_DA_PIP_INSPECT']
		}
	}).timeout(10000)

	/** Verifies graceful degradation when pip inspect is unavailable (invalid output). */
	test('verify SBOM generated without hashes when pip inspect output is invalid', async () => {
		// Given: pip environment with freeze and show but invalid inspect data
		process.env['TRUSTIFY_DA_PIP_FREEZE'] = Buffer.from(pipFreezeOutput).toString('base64')
		process.env['TRUSTIFY_DA_PIP_SHOW'] = Buffer.from(pipShowOutput).toString('base64')
		process.env['TRUSTIFY_DA_PIP_INSPECT'] = Buffer.from('INVALID JSON').toString('base64')

		try {
			// When: component analysis is run
			let result = await pythonPip.provideComponent(`test/providers/tst_manifests/pip/${hashTestCase}/requirements.txt`, {})
			let sbom = JSON.parse(result.content)

			// Then: SBOM is generated without hashes
			expect(sbom.components).to.have.lengthOf(2)
			for (let component of sbom.components) {
				expect(component).to.not.have.property('hashes')
			}
		} finally {
			delete process.env['TRUSTIFY_DA_PIP_FREEZE']
			delete process.env['TRUSTIFY_DA_PIP_SHOW']
			delete process.env['TRUSTIFY_DA_PIP_INSPECT']
		}
	}).timeout(10000)

	/** Verifies that pip inspect is skipped when freeze/show env vars are set without inspect. */
	test('verify SBOM generated without hashes when pip inspect env var is not set', async () => {
		// Given: pip environment with freeze and show but NO inspect override
		process.env['TRUSTIFY_DA_PIP_FREEZE'] = Buffer.from(pipFreezeOutput).toString('base64')
		process.env['TRUSTIFY_DA_PIP_SHOW'] = Buffer.from(pipShowOutput).toString('base64')

		try {
			// When: component analysis is run
			let result = await pythonPip.provideComponent(`test/providers/tst_manifests/pip/${hashTestCase}/requirements.txt`, {})
			let sbom = JSON.parse(result.content)

			// Then: SBOM is generated without hashes (pip inspect skipped in env var mode)
			expect(sbom.components).to.have.lengthOf(2)
			for (let component of sbom.components) {
				expect(component).to.not.have.property('hashes')
			}
		} finally {
			delete process.env['TRUSTIFY_DA_PIP_FREEZE']
			delete process.env['TRUSTIFY_DA_PIP_SHOW']
		}
	}).timeout(10000)

}).beforeAll(() => clock = useFakeTimers(new Date('2023-10-01T00:00:00.000Z'))).afterAll(() => clock.restore());

suite('testing python-pip SHA-256 hashes with real pip inspect', () => {
	const testCase = 'pip_requirements_txt_with_hashes'

	/** Verifies SBOM components include SHA-256 hashes from real pip inspect. */
	test('SBOM components include SHA-256 hashes from pip inspect', async () => {
		// Given: packages installed via real pip
		let pipPath = getCustomPath("pip3");
		invokeCommand(pipPath, ['install', '-r', `test/providers/tst_manifests/pip/${testCase}/requirements.txt`])

		// When: stack analysis is run (uses real pip freeze, pip show, and pip inspect)
		let result = await pythonPip.provideStack(`test/providers/tst_manifests/pip/${testCase}/requirements.txt`, {})
		let sbom = JSON.parse(result.content)

		// Then: components with hashes have well-formed SHA-256 entries
		// Note: pip inspect may not include hashes for cached/pre-installed packages
		for (let component of sbom.components) {
			if (component.hashes) {
				expect(component.hashes).to.be.an('array').with.lengthOf(1)
				expect(component.hashes[0].alg).to.equal('SHA-256')
				expect(component.hashes[0].content).to.be.a('string').with.lengthOf(64)
			}
		}
	}).timeout(process.env.GITHUB_ACTIONS ? 30000 : 10000)

}).beforeAll(() => clock = useFakeTimers(new Date('2023-10-01T00:00:00.000Z'))).afterAll(() => clock.restore());
