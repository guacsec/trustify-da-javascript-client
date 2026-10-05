import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import { expect } from 'chai'
import esmock from 'esmock'
import { stub } from 'sinon'

/**
 * Builds a minimal AnalysisReport fixture with one vulnerability and remediation.
 * @param {object} overrides
 * @returns {object}
 */
function buildAnalysisReport(overrides = {}) {
	const {
		depRef = 'pkg:maven/org.apache.commons/commons-text@1.9',
		fixedIn = ['pkg:maven/org.apache.commons/commons-text@1.10.0'],
		issueId = 'CVE-2022-42889',
		severity = 'CRITICAL',
		providerName = 'redhat',
		sourceName = 'osv',
	} = overrides

	return {
		providers: {
			[providerName]: {
				sources: {
					[sourceName]: {
						dependencies: [{
							ref: depRef,
							issues: [{
								id: issueId,
								severity,
								remediation: { fixedIn },
							}],
						}],
					},
				},
			},
		},
	}
}

/**
 * Creates a temporary directory with the given files.
 * @param {Object.<string, string>} files - filename → content map
 * @returns {{dir: string, cleanup: function}}
 */
function createTempDir(files = {}) {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'remediate-test-'))
	for (const [name, content] of Object.entries(files)) {
		const filePath = path.join(dir, name)
		fs.mkdirSync(path.dirname(filePath), { recursive: true })
		fs.writeFileSync(filePath, content, 'utf-8')
	}
	return {
		dir,
		cleanup: () => fs.rmSync(dir, { recursive: true, force: true }),
	}
}

const SAMPLE_POM = `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-text</artifactId>
      <version>1.9</version>
    </dependency>
  </dependencies>
</project>`

const SAMPLE_TOML = `[versions]
jackson = "2.14.0"

[libraries]
jackson-core = { module = "com.fasterxml.jackson.core:jackson-core", version.ref = "jackson" }
`

suite('remediate — runRemediation', () => {
	/** @type {function} */
	let runRemediation
	let requestStackStub
	let matchStub

	setup(async () => {
		requestStackStub = stub()
		matchStub = stub()

		const mod = await esmock('../src/remediate.js', {
			'../src/analysis.js': {
				default: {
					requestStack: requestStackStub,
				},
			},
			'../src/provider.js': {
				match: matchStub,
				availableProviders: [],
			},
			'../src/index.js': {
				selectTrustifyDABackend: () => 'https://da.example.com',
			},
		})
		runRemediation = mod.runRemediation
	})

	suite('dry-run mode', () => {
		/** Verifies that dry-run shows proposed changes without modifying files. */
		test('shows proposed changes without modifying files', async () => {
			// Given a pom.xml with a vulnerable dependency
			const { dir, cleanup } = createTempDir({ 'pom.xml': SAMPLE_POM })
			try {
				const pomPath = path.join(dir, 'pom.xml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'maven' }) })
				requestStackStub.resolves(buildAnalysisReport())

				// When running with --dry-run
				const result = await runRemediation(pomPath, { dryRun: true })

				// Then exit code should be 2 and file should not be modified
				expect(result.exitCode).to.equal(2)
				expect(result.remediations).to.have.lengthOf(1)
				expect(result.remediations[0].artifactId).to.equal('commons-text')
				expect(result.remediations[0].currentVersion).to.equal('1.9')
				expect(result.remediations[0].fixedInVersion).to.equal('1.10.0')
				expect(result.remediations[0].files).to.deep.equal([pomPath])
				expect(fs.readFileSync(pomPath, 'utf-8')).to.equal(SAMPLE_POM)
			} finally {
				cleanup()
			}
		})
	})

	suite('apply mode', () => {
		/** Verifies that apply mode modifies the manifest file with remediated versions. */
		test('modifies pom.xml with remediated versions', async () => {
			// Given a pom.xml with a vulnerable dependency
			const { dir, cleanup } = createTempDir({ 'pom.xml': SAMPLE_POM })
			try {
				const pomPath = path.join(dir, 'pom.xml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'maven' }) })
				requestStackStub.resolves(buildAnalysisReport())

				// When running in apply mode (default)
				const result = await runRemediation(pomPath, {})

				// Then file should be modified and exit code should be 0
				expect(result.exitCode).to.equal(0)
				const updatedContent = fs.readFileSync(pomPath, 'utf-8')
				expect(updatedContent).to.include('1.10.0')
				expect(updatedContent).to.not.include('>1.9<')
				// The written manifest is reported in appliedFiles
				expect(result.appliedFiles).to.deep.equal([pomPath])
			} finally {
				cleanup()
			}
		})

		/**
		 * A dependency surfaced by analysis but not locatable in the manifest (e.g. a
		 * transitive dep, or a version managed in a parent POM) yields a remediation but
		 * no write. appliedFiles must stay empty so callers don't over-report "updated N
		 * files" — the bug ruromero flagged where the CLI counted r.files instead.
		 */
		test('omits from appliedFiles a manifest that received no write', async () => {
			const { dir, cleanup } = createTempDir({ 'pom.xml': SAMPLE_POM })
			try {
				const pomPath = path.join(dir, 'pom.xml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'maven' }) })
				// A vulnerable dep that is NOT declared in SAMPLE_POM — the updater applies nothing.
				requestStackStub.resolves(buildAnalysisReport({
					depRef: 'pkg:maven/com.transitive/deep-lib@1.0',
					fixedIn: ['pkg:maven/com.transitive/deep-lib@1.1'],
				}))

				const before = fs.readFileSync(pomPath, 'utf-8')
				const result = await runRemediation(pomPath, {})

				// The remediation is still reported, but nothing was written.
				expect(result.remediations.length).to.be.greaterThan(0)
				expect(result.appliedFiles).to.deep.equal([])
				expect(fs.readFileSync(pomPath, 'utf-8')).to.equal(before)
			} finally {
				cleanup()
			}
		})

		/** Verifies idempotency — running apply twice produces no diff on second run. */
		test('is idempotent — second apply produces no additional changes', async () => {
			// Given a pom.xml already updated
			const { dir, cleanup } = createTempDir({ 'pom.xml': SAMPLE_POM })
			try {
				const pomPath = path.join(dir, 'pom.xml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'maven' }) })
				requestStackStub.resolves(buildAnalysisReport())

				// When applying twice
				await runRemediation(pomPath, {})
				const afterFirst = fs.readFileSync(pomPath, 'utf-8')

				// Reset stubs for second call — now the version is already 1.10.0
				// so extractRemediations returns empty (currentVersion matches fixedInVersion)
				requestStackStub.resolves(buildAnalysisReport({
					depRef: 'pkg:maven/org.apache.commons/commons-text@1.10.0',
					fixedIn: ['pkg:maven/org.apache.commons/commons-text@1.10.0'],
				}))

				await runRemediation(pomPath, {})
				const afterSecond = fs.readFileSync(pomPath, 'utf-8')

				// Then the file should be identical after the second run
				expect(afterFirst).to.equal(afterSecond)
			} finally {
				cleanup()
			}
		})
	})

	suite('TOML manifest support', () => {
		/** Verifies that TOML version catalog files are updated correctly. */
		test('modifies libs.versions.toml with remediated versions', async () => {
			// Given a TOML version catalog with a vulnerable dependency
			const { dir, cleanup } = createTempDir({ 'libs.versions.toml': SAMPLE_TOML })
			try {
				const tomlPath = path.join(dir, 'libs.versions.toml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'gradle' }) })
				requestStackStub.resolves(buildAnalysisReport({
					depRef: 'pkg:maven/com.fasterxml.jackson.core/jackson-core@2.14.0',
					fixedIn: ['pkg:maven/com.fasterxml.jackson.core/jackson-core@2.15.0'],
				}))

				// When running in apply mode (default)
				const result = await runRemediation(tomlPath, {})

				// Then the TOML should be updated
				expect(result.exitCode).to.equal(0)
				const updatedContent = fs.readFileSync(tomlPath, 'utf-8')
				expect(updatedContent).to.include('2.15.0')
			} finally {
				cleanup()
			}
		})
	})

	suite('directory mode', () => {
		/** Verifies that directory mode discovers and processes all manifest files. */
		test('discovers and processes pom.xml and TOML files', async () => {
			// Given a directory with both pom.xml and TOML manifests
			const { dir, cleanup } = createTempDir({
				'module-a/pom.xml': SAMPLE_POM,
				'module-b/libs.versions.toml': SAMPLE_TOML,
			})
			try {
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'maven' }) })

				// Different responses for different manifests
				requestStackStub.onFirstCall().resolves(buildAnalysisReport())
				requestStackStub.onSecondCall().resolves(buildAnalysisReport({
					depRef: 'pkg:maven/com.fasterxml.jackson.core/jackson-core@2.14.0',
					fixedIn: ['pkg:maven/com.fasterxml.jackson.core/jackson-core@2.15.0'],
				}))

				// When running in apply mode (default) on the directory
				const result = await runRemediation(dir, {})

				// Then both manifests should yield remediations tagged with their file
				expect(result.exitCode).to.equal(0)
				expect(result.remediations).to.have.lengthOf(2)
				const remediatedFiles = result.remediations.flatMap(r => r.files)
				expect(remediatedFiles).to.include(path.join(dir, 'module-a', 'pom.xml'))
				expect(remediatedFiles).to.include(path.join(dir, 'module-b', 'libs.versions.toml'))
			} finally {
				cleanup()
			}
		})

		/** Verifies that empty directory returns exit code 0 with informative message. */
		test('returns exit code 0 when no manifests found', async () => {
			// Given an empty directory
			const { dir, cleanup } = createTempDir({})
			try {
				const result = await runRemediation(dir)

				expect(result.exitCode).to.equal(0)
				expect(result.remediations).to.deep.equal([])
			} finally {
				cleanup()
			}
		})
	})

	suite('provider filtering', () => {
		/** Verifies that --providers flag is passed through to analysis request. */
		test('passes providers to analysis request opts', async () => {
			// Given a pom.xml
			const { dir, cleanup } = createTempDir({ 'pom.xml': SAMPLE_POM })
			try {
				const pomPath = path.join(dir, 'pom.xml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'maven' }) })
				requestStackStub.resolves({ providers: {} })

				// When running with --providers
				await runRemediation(pomPath, { providers: 'redhat,lightwell', dryRun: true })

				// Then the opts should contain TRUSTIFY_DA_PROVIDERS
				const callOpts = requestStackStub.firstCall.args[4]
				expect(callOpts.TRUSTIFY_DA_PROVIDERS).to.equal('redhat,lightwell')
			} finally {
				cleanup()
			}
		})
	})

	suite('exit codes', () => {
		/** Verifies exit code 0 when no remediations are found. */
		test('exit code 0 when no remediations found', async () => {
			const { dir, cleanup } = createTempDir({ 'pom.xml': SAMPLE_POM })
			try {
				const pomPath = path.join(dir, 'pom.xml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'maven' }) })
				requestStackStub.resolves({ providers: {} })

				const result = await runRemediation(pomPath, { dryRun: true })

				expect(result.exitCode).to.equal(0)
				expect(result.remediations).to.deep.equal([])
			} finally {
				cleanup()
			}
		})

		/** Verifies exit code 2 for dry-run with remediations found. */
		test('exit code 2 for dry-run with remediations', async () => {
			const { dir, cleanup } = createTempDir({ 'pom.xml': SAMPLE_POM })
			try {
				const pomPath = path.join(dir, 'pom.xml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'maven' }) })
				requestStackStub.resolves(buildAnalysisReport())

				const result = await runRemediation(pomPath, { dryRun: true })

				expect(result.exitCode).to.equal(2)
			} finally {
				cleanup()
			}
		})
	})

	suite('error handling', () => {
		/** Verifies that unsupported manifest types throw an error. */
		test('throws for unsupported manifest type', async () => {
			const { dir, cleanup } = createTempDir({ 'requirements.txt': 'flask==2.0' })
			try {
				const filePath = path.join(dir, 'requirements.txt')
				try {
					await runRemediation(filePath)
					expect.fail('should have thrown')
				} catch (err) {
					expect(err.message).to.include('Unsupported manifest type')
				}
			} finally {
				cleanup()
			}
		})
	})

	suite('structured output', () => {
		/** Verifies that runRemediation returns the full structured remediation shape. */
		test('returns structured remediations with vulnerabilities, provider and files', async () => {
			const { dir, cleanup } = createTempDir({ 'pom.xml': SAMPLE_POM })
			try {
				const pomPath = path.join(dir, 'pom.xml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'maven' }) })
				requestStackStub.resolves(buildAnalysisReport())

				const result = await runRemediation(pomPath, {})

				expect(result.exitCode).to.equal(0)
				expect(result.remediations).to.have.lengthOf(1)
				const rem = result.remediations[0]
				expect(rem.groupId).to.equal('org.apache.commons')
				expect(rem.artifactId).to.equal('commons-text')
				expect(rem.currentVersion).to.equal('1.9')
				expect(rem.fixedInVersion).to.equal('1.10.0')
				expect(rem.vulnerabilities).to.have.lengthOf(1)
				expect(rem.vulnerabilities[0].id).to.equal('CVE-2022-42889')
				expect(rem.vulnerabilities[0].severity).to.equal('CRITICAL')
				expect(rem.provider).to.equal('redhat')
				expect(rem.files).to.deep.equal([pomPath])
			} finally {
				cleanup()
			}
		})
	})

	suite('per-dependency changes', () => {
		const MULTI_POM = `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-text</artifactId>
      <version>1.9</version>
    </dependency>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-core</artifactId>
      <version>2.14.0</version>
    </dependency>
  </dependencies>
</project>`

		const SHARED_PROP_POM = `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <properties>
    <commons.version>1.9</commons.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-text</artifactId>
      <version>\${commons.version}</version>
    </dependency>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>\${commons.version}</version>
    </dependency>
  </dependencies>
</project>`

		/**
		 * Builds an AnalysisReport containing several dependencies under one provider/source.
		 * @param {Array<{depRef: string, fixedIn: string[], issueId: string, severity?: string}>} deps
		 * @returns {object}
		 */
		function buildMultiDepReport(deps) {
			return {
				providers: {
					redhat: {
						sources: {
							osv: {
								dependencies: deps.map(d => ({
									ref: d.depRef,
									issues: [{
										id: d.issueId,
										severity: d.severity ?? 'HIGH',
										remediation: { fixedIn: d.fixedIn },
									}],
								})),
							},
						},
					},
				},
			}
		}

		/** Two independent deps in one pom -> two changes with distinct keys, each isolated. */
		test('two separate deps in one pom produce distinct changeKeys and isolated diffs', async () => {
			const { dir, cleanup } = createTempDir({ 'pom.xml': MULTI_POM })
			try {
				const pomPath = path.join(dir, 'pom.xml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'maven' }) })
				requestStackStub.resolves(buildMultiDepReport([
					{ depRef: 'pkg:maven/org.apache.commons/commons-text@1.9', fixedIn: ['pkg:maven/org.apache.commons/commons-text@1.10.0'], issueId: 'CVE-2022-42889' },
					{ depRef: 'pkg:maven/com.fasterxml.jackson.core/jackson-core@2.14.0', fixedIn: ['pkg:maven/com.fasterxml.jackson.core/jackson-core@2.15.0'], issueId: 'CVE-2020-1000' },
				]))

				const result = await runRemediation(pomPath, { dryRun: true, perDependencyChanges: true })

				expect(result.remediations).to.have.lengthOf(2)
				const text = result.remediations.find(r => r.artifactId === 'commons-text')
				const jackson = result.remediations.find(r => r.artifactId === 'jackson-core')

				// Each remediation has exactly one isolated change, keyed distinctly.
				expect(text.changes).to.have.lengthOf(1)
				expect(jackson.changes).to.have.lengthOf(1)
				expect(text.changes[0].changeKey).to.not.equal(jackson.changes[0].changeKey)
				expect(text.changes[0].changeKey).to.equal(`mvn:direct:${pomPath}:org.apache.commons:commons-text`)
				expect(text.changes[0].path).to.equal(pomPath)

				// commons-text's isolated 'after' bumps ONLY commons-text; jackson stays untouched.
				expect(text.changes[0].after).to.include('1.10.0')
				expect(text.changes[0].after).to.include('2.14.0')
				expect(text.changes[0].after).to.not.include('2.15.0')

				// dry-run must not touch the working tree.
				expect(fs.readFileSync(pomPath, 'utf-8')).to.equal(MULTI_POM)
			} finally {
				cleanup()
			}
		})

		/** Two deps sharing one ${property} are inseparable -> identical changeKey. */
		test('two deps sharing a maven property collapse to one changeKey', async () => {
			const { dir, cleanup } = createTempDir({ 'pom.xml': SHARED_PROP_POM })
			try {
				const pomPath = path.join(dir, 'pom.xml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'maven' }) })
				requestStackStub.resolves(buildMultiDepReport([
					{ depRef: 'pkg:maven/org.apache.commons/commons-text@1.9', fixedIn: ['pkg:maven/org.apache.commons/commons-text@1.10.0'], issueId: 'CVE-2022-42889' },
					{ depRef: 'pkg:maven/org.apache.commons/commons-lang3@1.9', fixedIn: ['pkg:maven/org.apache.commons/commons-lang3@1.10.0'], issueId: 'CVE-2021-2000' },
				]))

				const result = await runRemediation(pomPath, { dryRun: true, perDependencyChanges: true })

				expect(result.remediations).to.have.lengthOf(2)
				const text = result.remediations.find(r => r.artifactId === 'commons-text')
				const lang3 = result.remediations.find(r => r.artifactId === 'commons-lang3')

				// Both resolve to the same <properties> line -> same key -> one PR.
				const expectedKey = `mvn:prop:${pomPath}:commons.version`
				expect(text.changes[0].changeKey).to.equal(expectedKey)
				expect(lang3.changes[0].changeKey).to.equal(expectedKey)
				expect(text.changes[0].after).to.include('<commons.version>1.10.0</commons.version>')
			} finally {
				cleanup()
			}
		})

		/** Without the flag, no `changes` field is produced. */
		test('omits changes when perDependencyChanges is not set', async () => {
			const { dir, cleanup } = createTempDir({ 'pom.xml': SAMPLE_POM })
			try {
				const pomPath = path.join(dir, 'pom.xml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'maven' }) })
				requestStackStub.resolves(buildAnalysisReport())

				const result = await runRemediation(pomPath, { dryRun: true })

				expect(result.remediations[0].changes).to.equal(undefined)
			} finally {
				cleanup()
			}
		})

		/**
		 * Real-world scenario: stack analysis reports a vulnerable *transitive* dependency
		 * — present in the resolved tree but not declared in pom.xml. The isolated updater
		 * finds nothing to change for it, so it must be dropped rather than returned with an
		 * absent `changes` array; otherwise a caller iterating `remediation.changes` to build
		 * one PR per dependency would crash on `undefined`.
		 */
		test('drops a vulnerable transitive dependency absent from the manifest', async () => {
			const { dir, cleanup } = createTempDir({ 'pom.xml': SAMPLE_POM })
			try {
				const pomPath = path.join(dir, 'pom.xml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'maven' }) })
				// commons-text is declared directly (fixable); deep-lib is a transitive dep
				// surfaced by analysis but not present in pom.xml (unfixable in this manifest).
				requestStackStub.resolves(buildMultiDepReport([
					{ depRef: 'pkg:maven/org.apache.commons/commons-text@1.9', fixedIn: ['pkg:maven/org.apache.commons/commons-text@1.10.0'], issueId: 'CVE-2022-42889' },
					{ depRef: 'pkg:maven/com.transitive/deep-lib@1.0', fixedIn: ['pkg:maven/com.transitive/deep-lib@1.1'], issueId: 'CVE-2023-9999' },
				]))

				const result = await runRemediation(pomPath, { dryRun: true, perDependencyChanges: true })

				// Only the directly-declared dependency survives; the transitive one is dropped.
				expect(result.remediations).to.have.lengthOf(1)
				expect(result.remediations[0].artifactId).to.equal('commons-text')

				// Every returned remediation carries a usable changes array, so a caller can
				// build isolated PRs without a guard and without crashing on `undefined`.
				expect(result.remediations.every(r => Array.isArray(r.changes) && r.changes.length > 0)).to.equal(true)
				expect(() => result.remediations.flatMap(r => r.changes)).to.not.throw()
			} finally {
				cleanup()
			}
		})
	})

	suite('exclude filter', () => {
		/**
		 * Builds an AnalysisReport containing several dependencies under one provider/source.
		 * @param {Array<{depRef: string, fixedIn: string[], issueId: string, severity?: string}>} deps
		 * @returns {object}
		 */
		function buildExcludeReport(deps) {
			return {
				providers: {
					redhat: {
						sources: {
							osv: {
								dependencies: deps.map(d => ({
									ref: d.depRef,
									issues: [{
										id: d.issueId,
										severity: d.severity ?? 'HIGH',
										remediation: { fixedIn: d.fixedIn },
									}],
								})),
							},
						},
					},
				},
			}
		}

		const COMMONS_TEXT = { depRef: 'pkg:maven/org.apache.commons/commons-text@1.9', fixedIn: ['pkg:maven/org.apache.commons/commons-text@1.10.0'], issueId: 'CVE-2022-42889' }
		const JACKSON_CORE = { depRef: 'pkg:maven/com.fasterxml.jackson.core/jackson-core@2.14.0', fixedIn: ['pkg:maven/com.fasterxml.jackson.core/jackson-core@2.15.0'], issueId: 'CVE-2020-1000' }
		const LOG4J = { depRef: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0', fixedIn: ['pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1'], issueId: 'CVE-2021-44228' }

		/** An excluded purl (matched without its @version) is absent from the result. */
		test('excluded purl is absent from result.remediations', async () => {
			const { dir, cleanup } = createTempDir({ 'pom.xml': SAMPLE_POM })
			try {
				const pomPath = path.join(dir, 'pom.xml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'maven' }) })
				requestStackStub.resolves(buildExcludeReport([COMMONS_TEXT]))

				const result = await runRemediation(pomPath, { dryRun: true, exclude: ['pkg:maven/org.apache.commons/commons-text'] })

				expect(result.remediations).to.have.lengthOf(0)
				expect(result.remediations.map(r => r.artifactId)).to.not.include('commons-text')
			} finally {
				cleanup()
			}
		})

		/** Non-excluded purls survive even when an exclude list is present. */
		test('non-excluded purls are present when an exclude list is non-empty', async () => {
			const { dir, cleanup } = createTempDir({ 'pom.xml': SAMPLE_POM })
			try {
				const pomPath = path.join(dir, 'pom.xml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'maven' }) })
				requestStackStub.resolves(buildExcludeReport([COMMONS_TEXT, JACKSON_CORE]))

				const result = await runRemediation(pomPath, { dryRun: true, exclude: ['pkg:maven/org.apache.commons/commons-text'] })

				const artifacts = result.remediations.map(r => r.artifactId)
				expect(artifacts).to.not.include('commons-text')
				expect(artifacts).to.include('jackson-core')
			} finally {
				cleanup()
			}
		})

		/** An empty exclude list behaves identically to omitting the option. */
		test('empty exclude list produces the same results as omitting the option', async () => {
			const { dir, cleanup } = createTempDir({ 'pom.xml': SAMPLE_POM })
			try {
				const pomPath = path.join(dir, 'pom.xml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'maven' }) })
				requestStackStub.resolves(buildExcludeReport([COMMONS_TEXT, JACKSON_CORE]))

				const withEmpty = await runRemediation(pomPath, { dryRun: true, exclude: [] })
				const withOmitted = await runRemediation(pomPath, { dryRun: true })

				expect(withEmpty.remediations.map(r => r.artifactId).sort())
					.to.deep.equal(withOmitted.remediations.map(r => r.artifactId).sort())
				expect(withEmpty.remediations).to.have.lengthOf(2)
			} finally {
				cleanup()
			}
		})

		/** Every entry in a multi-entry exclude list filters its matching purl. */
		test('multiple exclude entries each filter correctly', async () => {
			const { dir, cleanup } = createTempDir({ 'pom.xml': SAMPLE_POM })
			try {
				const pomPath = path.join(dir, 'pom.xml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'maven' }) })
				requestStackStub.resolves(buildExcludeReport([COMMONS_TEXT, JACKSON_CORE, LOG4J]))

				const result = await runRemediation(pomPath, {
					dryRun: true,
					exclude: [
						'pkg:maven/org.apache.commons/commons-text',
						'pkg:maven/com.fasterxml.jackson.core/jackson-core',
					],
				})

				const artifacts = result.remediations.map(r => r.artifactId)
				expect(artifacts).to.deep.equal(['log4j-core'])
			} finally {
				cleanup()
			}
		})

		/** A `*` wildcard excludes every artifact under a group. */
		test('wildcard pattern excludes a whole group', async () => {
			const { dir, cleanup } = createTempDir({ 'pom.xml': SAMPLE_POM })
			try {
				const pomPath = path.join(dir, 'pom.xml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'maven' }) })
				requestStackStub.resolves(buildExcludeReport([
					COMMONS_TEXT,
					{ depRef: 'pkg:maven/org.apache.commons/commons-lang3@3.9', fixedIn: ['pkg:maven/org.apache.commons/commons-lang3@3.12.0'], issueId: 'CVE-2021-2000' },
					JACKSON_CORE,
				]))

				const result = await runRemediation(pomPath, { dryRun: true, exclude: ['pkg:maven/org.apache.commons/*'] })

				const artifacts = result.remediations.map(r => r.artifactId)
				expect(artifacts).to.deep.equal(['jackson-core'])
			} finally {
				cleanup()
			}
		})

		/** A `*` wildcard matches within the name segment too. */
		test('wildcard pattern matches a partial name', async () => {
			const { dir, cleanup } = createTempDir({ 'pom.xml': SAMPLE_POM })
			try {
				const pomPath = path.join(dir, 'pom.xml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'maven' }) })
				requestStackStub.resolves(buildExcludeReport([COMMONS_TEXT, JACKSON_CORE]))

				const result = await runRemediation(pomPath, { dryRun: true, exclude: ['pkg:maven/org.apache.commons/commons-*'] })

				const artifacts = result.remediations.map(r => r.artifactId)
				expect(artifacts).to.deep.equal(['jackson-core'])
			} finally {
				cleanup()
			}
		})

		/** A `**` globstar crosses `/` segments, excluding a whole ecosystem. */
		test('globstar pattern excludes an entire ecosystem across segments', async () => {
			const { dir, cleanup } = createTempDir({ 'pom.xml': SAMPLE_POM })
			try {
				const pomPath = path.join(dir, 'pom.xml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'maven' }) })
				requestStackStub.resolves(buildExcludeReport([
					COMMONS_TEXT,
					JACKSON_CORE,
					{ depRef: 'pkg:npm/%40babel/traverse@7.0.0', fixedIn: ['pkg:npm/%40babel/traverse@7.23.2'], issueId: 'CVE-2023-45133' },
				]))

				// `*` would not cross the namespace/name boundary; `**` does.
				const result = await runRemediation(pomPath, { dryRun: true, exclude: ['pkg:maven/**'] })

				const artifacts = result.remediations.map(r => r.artifactId)
				expect(artifacts).to.deep.equal(['traverse'])
			} finally {
				cleanup()
			}
		})

		/** The purl `type` is matched case-insensitively (purl types are case-insensitive). */
		test('exclude type is matched case-insensitively', async () => {
			const { dir, cleanup } = createTempDir({ 'pom.xml': SAMPLE_POM })
			try {
				const pomPath = path.join(dir, 'pom.xml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'maven' }) })
				requestStackStub.resolves(buildExcludeReport([COMMONS_TEXT]))

				const result = await runRemediation(pomPath, { dryRun: true, exclude: ['pkg:MAVEN/org.apache.commons/commons-text'] })

				expect(result.remediations).to.have.lengthOf(0)
			} finally {
				cleanup()
			}
		})

		/** Excluding one dep that shares a Maven ${property} with a retained dep also blocks the retained one. */
		test('shared Maven property blocks retained dep when the co-dependent is excluded', async () => {
			const SHARED_PROP_POM = `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <properties>
    <commons.version>1.9</commons.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-text</artifactId>
      <version>\${commons.version}</version>
    </dependency>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>\${commons.version}</version>
    </dependency>
  </dependencies>
</project>`
			const { dir, cleanup } = createTempDir({ 'pom.xml': SHARED_PROP_POM })
			try {
				const pomPath = path.join(dir, 'pom.xml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'maven' }) })
				requestStackStub.resolves(buildExcludeReport([
					COMMONS_TEXT,
					{ depRef: 'pkg:maven/org.apache.commons/commons-lang3@1.9', fixedIn: ['pkg:maven/org.apache.commons/commons-lang3@1.10.0'], issueId: 'CVE-2021-2000' },
				]))

				const result = await runRemediation(pomPath, {
					dryRun: true,
					exclude: ['pkg:maven/org.apache.commons/commons-text'],
				})

				// commons-lang3 shares ${commons.version} with the excluded commons-text,
				// so it must also be blocked — bumping the property would upgrade both.
				expect(result.remediations).to.have.lengthOf(0)
				expect(result.skipped).to.have.lengthOf(1)
				expect(result.skipped[0].artifactId).to.equal('commons-lang3')
				expect(result.skipped[0].reason).to.equal('Shares a Maven property with excluded dependency org.apache.commons:commons-text')
				expect(fs.readFileSync(pomPath, 'utf-8')).to.equal(SHARED_PROP_POM)
			} finally {
				cleanup()
			}
		})

		/** Excluding one dep that shares a Maven ${property} blocks that property but not independent deps. */
		test('shared property blocks co-dependents but not independent deps', async () => {
			const MIXED_POM = `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <properties>
    <commons.version>1.9</commons.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-text</artifactId>
      <version>\${commons.version}</version>
    </dependency>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>\${commons.version}</version>
    </dependency>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-core</artifactId>
      <version>2.14.0</version>
    </dependency>
  </dependencies>
</project>`
			const { dir, cleanup } = createTempDir({ 'pom.xml': MIXED_POM })
			try {
				const pomPath = path.join(dir, 'pom.xml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'maven' }) })
				requestStackStub.resolves(buildExcludeReport([
					COMMONS_TEXT,
					{ depRef: 'pkg:maven/org.apache.commons/commons-lang3@1.9', fixedIn: ['pkg:maven/org.apache.commons/commons-lang3@1.10.0'], issueId: 'CVE-2021-2000' },
					JACKSON_CORE,
				]))

				const result = await runRemediation(pomPath, {
					dryRun: true,
					exclude: ['pkg:maven/org.apache.commons/commons-text'],
				})

				// commons-lang3 is blocked (shared property), but jackson-core is independent
				const artifacts = result.remediations.map(r => r.artifactId)
				expect(artifacts).to.not.include('commons-text')
				expect(artifacts).to.not.include('commons-lang3')
				expect(artifacts).to.deep.equal(['jackson-core'])
				expect(result.skipped).to.have.lengthOf(1)
				expect(result.skipped[0].artifactId).to.equal('commons-lang3')
			} finally {
				cleanup()
			}
		})

		/** An npm scope matches whether written `@scope` or percent-encoded `%40scope`. */
		test('npm scope matches regardless of percent-encoding', async () => {
			const { dir, cleanup } = createTempDir({ 'pom.xml': SAMPLE_POM })
			try {
				const pomPath = path.join(dir, 'pom.xml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'npm' }) })
				requestStackStub.resolves(buildExcludeReport([
					{ depRef: 'pkg:npm/%40babel/traverse@7.0.0', fixedIn: ['pkg:npm/%40babel/traverse@7.23.2'], issueId: 'CVE-2023-45133' },
					JACKSON_CORE,
				]))

				const withPlainScope = await runRemediation(pomPath, { dryRun: true, exclude: ['pkg:npm/@babel/traverse'] })
				const withEncodedScope = await runRemediation(pomPath, { dryRun: true, exclude: ['pkg:npm/%40babel/traverse'] })

				expect(withPlainScope.remediations.map(r => r.artifactId)).to.deep.equal(['jackson-core'])
				expect(withEncodedScope.remediations.map(r => r.artifactId)).to.deep.equal(['jackson-core'])
			} finally {
				cleanup()
			}
		})
	})
})
