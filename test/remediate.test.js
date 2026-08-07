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
		fixedIn = 'pkg:maven/org.apache.commons/commons-text@1.10.0',
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
				expect(result.output).to.include('commons-text')
				expect(result.output).to.include('1.9')
				expect(result.output).to.include('1.10.0')
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
					fixedIn: 'pkg:maven/org.apache.commons/commons-text@1.10.0',
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
					fixedIn: 'pkg:maven/com.fasterxml.jackson.core/jackson-core@2.15.0',
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
					fixedIn: 'pkg:maven/com.fasterxml.jackson.core/jackson-core@2.15.0',
				}))

				// When running in apply mode (default) on the directory
				const result = await runRemediation(dir, {})

				// Then both files should be processed
				expect(result.exitCode).to.equal(0)
				expect(result.output).to.include('Updated')
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
				expect(result.output).to.include('No supported manifest files found')
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
				expect(result.output).to.include('No remediations found')
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

	suite('group-by option', () => {
		/** Verifies that --group-by bundle produces a bundled report. */
		test('produces bundled report with group-by bundle', async () => {
			const { dir, cleanup } = createTempDir({ 'pom.xml': SAMPLE_POM })
			try {
				const pomPath = path.join(dir, 'pom.xml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'maven' }) })
				requestStackStub.resolves(buildAnalysisReport())

				// When running without dry-run and with group-by bundle
				const result = await runRemediation(pomPath, { groupBy: 'bundle' })

				// Then the output should contain bundled report markers
				expect(result.exitCode).to.equal(0)
				expect(result.output).to.include('Security Update Summary')
			} finally {
				cleanup()
			}
		})
	})
})
