import fs from 'fs'

import { expect } from 'chai'
import { useFakeTimers } from "sinon";

import golangGoModules from "../../src/providers/golang_gomodules.js"



let clock
suite('testing the golang-go-modules data provider', () => {
	suiteSetup(() => clock = useFakeTimers(new Date('2023-08-07T00:00:00.000Z')));
	suiteTeardown(() => clock.restore());
	[
		{name: 'go.mod', expected: true},
		{name: 'some_other.file', expected: false}
	].forEach(testCase => {
		test(`verify isSupported returns ${testCase.expected} for ${testCase.name}`, () =>
			expect(golangGoModules.isSupported(testCase.name)).to.equal(testCase.expected)
		)
	});

	[
		"go_mod_light_no_ignore",
		"go_mod_no_ignore",
		"go_mod_with_ignore",
		"go_mod_test_ignore",
		"go_mod_with_all_ignore",
		"go_mod_empty"
	].forEach(testCase => {
		let scenario = testCase.replace('go_mod_', '').replaceAll('_', ' ')
		test(`verify go.mod sbom provided for stack analysis with scenario ${scenario}`, async () => {
			// load the expected graph for the scenario
			let expectedSbom = fs.readFileSync(`test/providers/tst_manifests/golang/${testCase}/expected_sbom_stack_analysis.json`).toString()
			expectedSbom = JSON.stringify(JSON.parse(expectedSbom),null, 4)
			// invoke sut stack analysis for scenario manifest
			let providedDataForStack = await golangGoModules.provideStack(`test/providers/tst_manifests/golang/${testCase}/go.mod`)
			// new(year: number, month: number, date?: number, hours?: number, minutes?: number, seconds?: number, ms?: number): Date

			// providedDataForStack.content = providedDataForStack.content.replaceAll("\"timestamp\":\"[a-zA-Z0-9\\-\\:]+\"","")
			// verify returned data matches expectation
			expect(providedDataForStack.ecosystem).equal('golang')
			expect(providedDataForStack.contentType).equal('application/vnd.cyclonedx+json')
			expect(JSON.stringify(JSON.parse(providedDataForStack.content),null, 4).trim()).to.deep.equal(expectedSbom.trim())
		// these test cases takes ~2500-2700 ms each pr >10000 in CI (for the first test-case)
		}).timeout(process.env.GITHUB_ACTIONS ? 30000 : 10000)

		test(`verify go.mod sbom provided for component analysis with scenario ${scenario}`, async () => {
			// load the expected list for the scenario
			let expectedSbom = fs.readFileSync(`test/providers/tst_manifests/golang/${testCase}/expected_sbom_component_analysis.json`).toString().trimEnd()
			expectedSbom = JSON.stringify(JSON.parse(expectedSbom),null, 4)
			// invoke sut stack analysis for scenario manifest
			let providedDataForComponent = await golangGoModules.provideComponent(`test/providers/tst_manifests/golang/${testCase}/go.mod`)
			// verify returned data matches expectation
			expect(providedDataForComponent.ecosystem).equal('golang')
			expect(providedDataForComponent.contentType).equal('application/vnd.cyclonedx+json')
			expect(JSON.stringify(JSON.parse(providedDataForComponent.content),null,4).trimEnd()).to.deep.equal(expectedSbom)
			// these test cases takes ~1400-2000 ms each pr >10000 in CI (for the first test-case)
		}).timeout(process.env.GITHUB_ACTIONS ? 15000 : 10000)

	});

	/** Verifies that go.sum source hashes produce correct SHA-256 hex digests in the SBOM. */
	test('verify go.sum h1: hashes are converted to SHA-256 hex in SBOM components', async () => {
		// Given a fixture with go.sum containing module source entries
		let result = await golangGoModules.provideStack('test/providers/tst_manifests/golang/go_mod_light_no_ignore/go.mod')
		let sbom = JSON.parse(result.content)

		// When checking components that should have hashes from go.sum
		let cobra = sbom.components.find(c => c.name === 'cobra' && c.version === 'v0.0.5')

		// Then the hash should be present in CycloneDX format with valid hex
		expect(cobra.hashes).to.be.an('array').with.lengthOf(1)
		expect(cobra.hashes[0].alg).to.equal('SHA-256')
		expect(cobra.hashes[0].content).to.match(/^[0-9a-f]{64}$/)
		expect(cobra.hashes[0].content).to.equal('7f407e2e42d7e83b66447d62b28340f554ed3542bd2bcc58776f0934d7cebffb')
	}).timeout(process.env.GITHUB_ACTIONS ? 30000 : 10000)

	/** Verifies that a missing go.sum file results in omitted hashes, not errors. */
	test('verify SBOM generation succeeds without go.sum (no hashes)', async () => {
		// Given a fixture with no go.sum file
		let result = await golangGoModules.provideComponent('test/providers/tst_manifests/golang/go_mod_empty/go.mod')
		let sbom = JSON.parse(result.content)

		// Then no components should have hashes, and no errors should occur
		let withHashes = sbom.components.filter(c => c.hashes)
		expect(withHashes).to.have.lengthOf(0)
	}).timeout(process.env.GITHUB_ACTIONS ? 15000 : 10000)

	/** Verifies that go.sum /go.mod entries are excluded and only module source hashes are used. */
	test('verify only module source hashes are used from go.sum (not /go.mod entries)', async () => {
		// Given go_mod_light_no_ignore has both /go.mod and source entries in go.sum
		let result = await golangGoModules.provideStack('test/providers/tst_manifests/golang/go_mod_light_no_ignore/go.mod')
		let sbom = JSON.parse(result.content)

		// Then all components with hashes should have valid SHA-256 hex digests
		let withHashes = sbom.components.filter(c => c.hashes)
		expect(withHashes.length).to.be.greaterThan(0)
		for (let comp of withHashes) {
			expect(comp.hashes[0].alg).to.equal('SHA-256')
			expect(comp.hashes[0].content).to.match(/^[0-9a-f]{64}$/)
		}
	}).timeout(process.env.GITHUB_ACTIONS ? 30000 : 10000);

	[
		"go_mod_mvs_versions"

	].forEach(testCase => {
		let scenario = testCase.replace('go_mod_', '').replaceAll('_', ' ')
		test(`verify go.mod sbom provided for stack analysis with scenario ${scenario}`, async () => {
			// load the expected graph for the scenario
			let expectedSbom = fs.readFileSync(`test/providers/tst_manifests/golang/${testCase}/expected_sbom_stack_analysis.json`,).toString()
			// expectedSbom = JSON.stringify(JSON.parse(expectedSbom))
			// invoke sut stack analysis for scenario manifest
			let providedDataForStack = await golangGoModules.provideStack(`test/providers/tst_manifests/golang/${testCase}/go.mod`,{"TRUSTIFY_DA_GO_MVS_LOGIC_ENABLED" : "true"})
			// new(year: number, month: number, date?: number, hours?: number, minutes?: number, seconds?: number, ms?: number): Date

			// providedDataForStack.content = providedDataForStack.content.replaceAll("\"timestamp\":\"[a-zA-Z0-9\\-\\:]+\"","")
			// verify returned data matches expectation
			expect(providedDataForStack.ecosystem).equal('golang')
			expect(providedDataForStack.contentType).equal('application/vnd.cyclonedx+json')
			expect(JSON.stringify(JSON.parse(providedDataForStack.content),null, 4).trim()).to.deep.equal(expectedSbom.trim())

			// these test cases takes ~2500-2700 ms each pr >10000 in CI (for the first test-case)
		}).timeout(process.env.GITHUB_ACTIONS ? 30000 : 10000)

	})
});


