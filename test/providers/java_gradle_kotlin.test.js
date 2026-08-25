import crypto from 'crypto'
import fs from 'fs'
import path from 'path'

import { expect } from 'chai'
import { spy, useFakeTimers } from "sinon";

import Java_gradle_kotlin from '../../src/providers/java_gradle_kotlin.js'

import {
	HASH_FIXTURE_DIR,
	artifactFileFor,
	buildHashScriptOutput,
	cleanupHashFixtures,
	getStubbedResponse,
	mockInvokeCommand,
} from './gradle_hash_test_utils.js'

let clock

suite('testing the java-gradle-kotlin data provider', () => {
	// Fake only Date (for deterministic SBOM timestamps); faking setImmediate/timers
	// would deadlock the streaming SHA-256 hash reader's event-based fs streams.
	suiteSetup(() => clock = useFakeTimers({ now: new Date('2023-08-07T00:00:00.000Z'), toFake: ['Date'] }));
	suiteTeardown(() => {
		clock.restore()
		cleanupHashFixtures()
	});

	[
		{ name: 'build.gradle.kts', expected: true },
		{ name: 'some_other.file', expected: false }
	].forEach(testCase => {
		test(`verify isSupported returns ${testCase.expected} for ${testCase.name}`, () => {
			let javaGradleProvider = new Java_gradle_kotlin()
			expect(javaGradleProvider.isSupported(testCase.name)).to.equal(testCase.expected)
		})
	});

	[
		"deps_with_no_ignore_common_paths",
		"deps_with_ignore_full_specification",
		"deps_with_ignore_named_params",
		"deps_with_ignore_notations"
	].forEach(testCase => {
		let scenario = testCase.replaceAll('_', ' ')

		test(`verify gradle data provided for stack analysis with scenario ${scenario}`, async () => {
			// load the expected graph for the scenario
			let expectedSbom = fs.readFileSync(`test/providers/tst_manifests/gradle/${testCase}/expected_stack_sbom.json`,).toString().trim()
			let dependencyTreeTextContent = fs.readFileSync(`test/providers/tst_manifests/gradle/${testCase}/depTree.txt`,).toString()
			let gradleProperties = fs.readFileSync(`test/providers/tst_manifests/gradle/${testCase}/gradle.properties`,).toString()
			let javGradleProvider = new Java_gradle_kotlin()
			mockInvokeCommand(javGradleProvider, dependencyTreeTextContent, gradleProperties)
			// invoke sut stack analysis for scenario manifest
			let providedDataForStack = await javGradleProvider.provideStack(`test/providers/tst_manifests/gradle/${testCase}/build.gradle.kts`)
			// verify returned data matches expectation exactly, including artifact hashes (SBOM_CASES deep-equal)
			expect(JSON.parse(providedDataForStack.content)).to.deep.equal(JSON.parse(expectedSbom));

			// these test cases takes ~2500-2700 ms each pr >10000 in CI (for the first test-case)
		}).timeout(process.env.GITHUB_ACTIONS ? 40000 : 10000)

		test(`verify gradle data provided for component analysis with scenario ${scenario}`, async () => {
			// load the expected list for the scenario
			let expectedSbom = fs.readFileSync(`test/providers/tst_manifests/gradle/${testCase}/expected_component_sbom.json`,).toString().trim()
			let dependencyTreeTextContent = fs.readFileSync(`test/providers/tst_manifests/gradle/${testCase}/depTree.txt`,).toString()
			let gradleProperties = fs.readFileSync(`test/providers/tst_manifests/gradle/${testCase}/gradle.properties`,).toString()
			let javaGradleProvider = new Java_gradle_kotlin()
			mockInvokeCommand(javaGradleProvider, dependencyTreeTextContent, gradleProperties)
			// invoke component analysis for scenario manifest
			let providedForComponent = await javaGradleProvider.provideComponent(`test/providers/tst_manifests/gradle/${testCase}/build.gradle.kts`, {})
			// verify returned data matches expectation exactly, including artifact hashes (SBOM_CASES deep-equal)
			expect(JSON.parse(providedForComponent.content)).to.deep.equal(JSON.parse(expectedSbom));
			// these test cases takes ~1400-2000 ms each pr >10000 in CI (for the first test-case)
		}).timeout(process.env.GITHUB_ACTIONS ? 15000 : 5000)
	});

	suite('artifact hash computation', () => {
		const testCase = 'deps_with_no_ignore_common_paths'
		const dir = `test/providers/tst_manifests/gradle/${testCase}`

		/** Verifies the SHA-256 the provider computes matches the digest of the resolved artifact file. */
		test('verify component hashes are the SHA-256 hex digest of the resolved artifact file', async () => {
			// Given a dependency tree whose artifacts hash to a known, deterministic digest
			let depTree = fs.readFileSync(`${dir}/depTree.txt`).toString()
			let props = fs.readFileSync(`${dir}/gradle.properties`).toString()
			let provider = new Java_gradle_kotlin()
			mockInvokeCommand(provider, depTree, props)

			// When building the component-analysis SBOM
			let sbom = JSON.parse((await provider.provideComponent(`${dir}/build.gradle.kts`, {})).content)

			// Then the direct dependency carries the SHA-256 of its artifact file content
			let coord = 'io.quarkus:quarkus-hibernate-orm:2.13.5.Final'
			let expectedDigest = crypto.createHash('sha256').update(coord).digest('hex')
			let component = sbom.components.find(c => c.name === 'quarkus-hibernate-orm' && c.version === '2.13.5.Final')
			expect(component.hashes).to.be.an('array').with.lengthOf(1)
			expect(component.hashes[0].alg).to.equal('SHA-256')
			expect(component.hashes[0].content).to.match(/^[0-9a-f]{64}$/)
			expect(component.hashes[0].content).to.equal(expectedDigest)
		}).timeout(10000)

		/** Verifies that a fileless artifact (e.g. a BOM/platform dependency) yields no hash while others keep theirs. */
		test('verify an artifact with no resolvable file has its hash omitted, others unaffected', async () => {
			// Given an init script that reports no file for one dependency (as a platform()/BOM would)
			let depTree = fs.readFileSync(`${dir}/depTree.txt`).toString()
			let props = fs.readFileSync(`${dir}/gradle.properties`).toString()
			let omitted = 'io.quarkus:quarkus-hibernate-orm:2.13.5.Final'
			let hashOutput = buildHashScriptOutput(depTree, coord => (coord === omitted ? null : artifactFileFor(coord)))
			let provider = new Java_gradle_kotlin()
			mockInvokeCommand(provider, depTree, props, hashOutput)

			// When building the component-analysis SBOM
			let sbom = JSON.parse((await provider.provideComponent(`${dir}/build.gradle.kts`, {})).content)

			// Then the fileless dependency has no hashes, while a sibling dependency still does
			let omittedComponent = sbom.components.find(c => c.name === 'quarkus-hibernate-orm')
			let otherComponent = sbom.components.find(c => c.name === 'quarkus-agroal')
			expect(omittedComponent.hashes).to.be.undefined
			expect(otherComponent.hashes).to.be.an('array').with.lengthOf(1)
		}).timeout(10000)

		/** Verifies the init script raising an error degrades to an SBOM without hashes rather than throwing. */
		test('verify a failing hash init script degrades to an SBOM without hashes', async () => {
			// Given a gradle binary that throws when the hash init script is invoked
			let depTree = fs.readFileSync(`${dir}/depTree.txt`).toString()
			let props = fs.readFileSync(`${dir}/gradle.properties`).toString()
			let provider = new Java_gradle_kotlin()
			Object.getPrototypeOf(Object.getPrototypeOf(provider))._invokeCommand = function (bin, args) {
				if (args.includes('daListHashes')) {
					throw new Error('init script failed')
				}
				return getStubbedResponse(args, depTree, props)
			}

			// When building the stack-analysis SBOM and Then no error is raised
			let result = await provider.provideStack(`${dir}/build.gradle.kts`)

			// And no component carries hashes
			let sbom = JSON.parse(result.content)
			expect(sbom.components.filter(c => c.hashes)).to.have.lengthOf(0)
		}).timeout(10000)

		/**
		 * Key drift (Maven lesson #1): both the stored key and the lookup key are built
		 * from the canonical PURL, so the map is keyed by `pkg:maven/...` strings and a
		 * conflict-resolved (`->`) transitive dependency still matches at its resolved version.
		 */
		test('verify the hash map is keyed by canonical PURL and conflict-resolved deps still match', async () => {
			// Given a tree containing "jboss-logging:3.4.3.Final -> 3.5.0.Final"
			let depTree = fs.readFileSync(`${dir}/depTree.txt`).toString()
			let props = fs.readFileSync(`${dir}/gradle.properties`).toString()
			let provider = new Java_gradle_kotlin()
			mockInvokeCommand(provider, depTree, props)

			// Then the hash map is keyed by canonical PURL strings, keyed at the resolved version
			let hashMap = await provider.parseGradleHashes(`${dir}/build.gradle.kts`)
			expect([...hashMap.keys()]).to.not.be.empty
			expect([...hashMap.keys()].every(k => k.startsWith('pkg:maven/'))).to.equal(true)
			expect(hashMap.has('pkg:maven/org.jboss.logging/jboss-logging@3.5.0.Final')).to.equal(true)

			// And end-to-end, that resolved transitive dependency carries its hash in the stack SBOM
			let sbom = JSON.parse((await provider.provideStack(`${dir}/build.gradle.kts`)).content)
			let comp = sbom.components.find(c => c.name === 'jboss-logging' && c.version === '3.5.0.Final')
			expect(comp.hashes).to.be.an('array').with.lengthOf(1)
		}).timeout(10000)

		/** Degradation warning (Maven lesson #2): a summary warning is emitted when some artifacts cannot be read. */
		test('verify a warning is emitted when some resolved artifacts cannot be read', async () => {
			// Given an init script that points one dependency at a nonexistent file
			let depTree = fs.readFileSync(`${dir}/depTree.txt`).toString()
			let props = fs.readFileSync(`${dir}/gradle.properties`).toString()
			let unreadable = 'io.quarkus:quarkus-hibernate-orm:2.13.5.Final'
			let hashOutput = buildHashScriptOutput(depTree, coord =>
				(coord === unreadable ? path.join(HASH_FIXTURE_DIR, 'does-not-exist.jar') : artifactFileFor(coord)))
			let provider = new Java_gradle_kotlin()
			mockInvokeCommand(provider, depTree, props, hashOutput)

			// When building the SBOM, a summary warning is emitted even without TRUSTIFY_DA_DEBUG
			let warn = spy(console, 'warn')
			try {
				await provider.provideComponent(`${dir}/build.gradle.kts`, {})
			} finally {
				warn.restore()
			}
			expect(warn.calledWithMatch(/could not be read/)).to.equal(true)
		}).timeout(10000)

		/** Degradation warning (Maven lesson #2): a failing hash init script emits a warning rather than degrading silently. */
		test('verify a warning is emitted when the hash init script fails', async () => {
			// Given a gradle binary that throws when the hash init script is invoked
			let depTree = fs.readFileSync(`${dir}/depTree.txt`).toString()
			let props = fs.readFileSync(`${dir}/gradle.properties`).toString()
			let provider = new Java_gradle_kotlin()
			Object.getPrototypeOf(Object.getPrototypeOf(provider))._invokeCommand = function (bin, args) {
				if (args.includes('daListHashes')) {
					throw new Error('init script failed')
				}
				return getStubbedResponse(args, depTree, props)
			}

			// When building the SBOM, the silent degradation is surfaced as a warning
			let warn = spy(console, 'warn')
			try {
				await provider.provideStack(`${dir}/build.gradle.kts`)
			} finally {
				warn.restore()
			}
			expect(warn.calledWithMatch(/without hashes/)).to.equal(true)
		}).timeout(10000)
	});

	[
		"deps_with_empty_project_group"
	].forEach(testCase => {
		let scenario = testCase.replaceAll('_', ' ')

		test(`verify gradle provider throws with scenario ${scenario}`, async () => {
			// load the expected list for the scenario
			let dependencyTreeTextContent = fs.readFileSync(`test/providers/tst_manifests/gradle/${testCase}/depTree.txt`,).toString()
			let gradleProperties = fs.readFileSync(`test/providers/tst_manifests/gradle/${testCase}/gradle.properties`,).toString()
			let provider = new Java_gradle_kotlin()
			mockInvokeCommand(provider, dependencyTreeTextContent, gradleProperties)
			// invoke component analysis for scenario manifest
			let error
			try {
				await provider.provideComponent(`test/providers/tst_manifests/gradle/${testCase}/build.gradle`, {})
			} catch (e) {
				error = e
			}
			expect(error).to.exist
		})
	})
});
