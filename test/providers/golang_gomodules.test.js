import fs from 'fs'

import { expect } from 'chai'
import { useFakeTimers } from "sinon";

import golangGoModules from "../../src/providers/golang_gomodules.js"



let clock
suite('testing the golang-go-modules data provider', () => {
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
		test(`verify go.mod sbom provided for stack analysis with scenario ${scenario}`, () => {
			// load the expected graph for the scenario
			let expectedSbom = fs.readFileSync(`test/providers/tst_manifests/golang/${testCase}/expected_sbom_stack_analysis.json`).toString()
			expectedSbom = JSON.stringify(JSON.parse(expectedSbom),null, 4)
			// invoke sut stack analysis for scenario manifest
			let providedDataForStack = golangGoModules.provideStack(`test/providers/tst_manifests/golang/${testCase}/go.mod`)
			// new(year: number, month: number, date?: number, hours?: number, minutes?: number, seconds?: number, ms?: number): Date

			// providedDataForStack.content = providedDataForStack.content.replaceAll("\"timestamp\":\"[a-zA-Z0-9\\-\\:]+\"","")
			// verify returned data matches expectation
			expect(providedDataForStack.ecosystem).equal('golang')
			expect(providedDataForStack.contentType).equal('application/vnd.cyclonedx+json')
			expect(JSON.stringify(JSON.parse(providedDataForStack.content),null, 4).trim()).to.deep.equal(expectedSbom.trim())
		// these test cases takes ~2500-2700 ms each pr >10000 in CI (for the first test-case)
		}).timeout(process.env.GITHUB_ACTIONS ? 30000 : 10000)

		test(`verify go.mod sbom provided for component analysis with scenario ${scenario}`, () => {
			// load the expected list for the scenario
			let expectedSbom = fs.readFileSync(`test/providers/tst_manifests/golang/${testCase}/expected_sbom_component_analysis.json`).toString().trimEnd()
			expectedSbom = JSON.stringify(JSON.parse(expectedSbom),null, 4)
			// invoke sut stack analysis for scenario manifest
			let providedDataForComponent = golangGoModules.provideComponent(`test/providers/tst_manifests/golang/${testCase}/go.mod`)
			// verify returned data matches expectation
			expect(providedDataForComponent.ecosystem).equal('golang')
			expect(providedDataForComponent.contentType).equal('application/vnd.cyclonedx+json')
			expect(JSON.stringify(JSON.parse(providedDataForComponent.content),null,4).trimEnd()).to.deep.equal(expectedSbom)
			// these test cases takes ~1400-2000 ms each pr >10000 in CI (for the first test-case)
		}).timeout(process.env.GITHUB_ACTIONS ? 15000 : 10000)

	});

	[
		"go_mod_mvs_versions"

	].forEach(testCase => {
		let scenario = testCase.replace('go_mod_', '').replaceAll('_', ' ')
		test(`verify go.mod sbom provided for stack analysis with scenario ${scenario}`, () => {
			// load the expected graph for the scenario
			let expectedSbom = fs.readFileSync(`test/providers/tst_manifests/golang/${testCase}/expected_sbom_stack_analysis.json`,).toString()
			// expectedSbom = JSON.stringify(JSON.parse(expectedSbom))
			// invoke sut stack analysis for scenario manifest
			let providedDataForStack = golangGoModules.provideStack(`test/providers/tst_manifests/golang/${testCase}/go.mod`,{"TRUSTIFY_DA_GO_MVS_LOGIC_ENABLED" : "true"})
			// new(year: number, month: number, date?: number, hours?: number, minutes?: number, seconds?: number, ms?: number): Date

			// providedDataForStack.content = providedDataForStack.content.replaceAll("\"timestamp\":\"[a-zA-Z0-9\\-\\:]+\"","")
			// verify returned data matches expectation
			expect(providedDataForStack.ecosystem).equal('golang')
			expect(providedDataForStack.contentType).equal('application/vnd.cyclonedx+json')
			expect(JSON.stringify(JSON.parse(providedDataForStack.content),null, 4).trim()).to.deep.equal(expectedSbom.trim())

			// these test cases takes ~2500-2700 ms each pr >10000 in CI (for the first test-case)
		}).timeout(process.env.GITHUB_ACTIONS ? 30000 : 10000)

	})
}).beforeAll(() => clock = useFakeTimers(new Date('2023-08-07T00:00:00.000Z'))).afterAll(()=> clock.restore());


