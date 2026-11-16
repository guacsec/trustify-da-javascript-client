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
	let discoverGradleSubprojectsStub
	let findNearestBuildFileStub

	setup(async () => {
		requestStackStub = stub()
		matchStub = stub()
		discoverGradleSubprojectsStub = stub().resolves([])
		findNearestBuildFileStub = stub().returns(undefined)

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
			'../src/providers/java_gradle.js': {
				discoverGradleSubprojects: discoverGradleSubprojectsStub,
				findNearestBuildFile: findNearestBuildFileStub,
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

				expect(result.remediations).to.have.lengthOf(0)
				expect(result.groups).to.have.lengthOf(0)
				expect(result.appliedFiles).to.deep.equal([])
				expect(result.skipped).to.have.lengthOf(1)
				expect(result.skipped[0].reason).to.equal('Dependency not directly declared in the manifest')
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

	suite('Gradle version catalog fan-out', () => {
		const CATALOG = `[versions]
commons = "3.16.0"

[libraries]
commons-lang3 = { module = "org.apache.commons:commons-lang3", version.ref = "commons" }
`

		const SUBPROJECT_REPORT = buildAnalysisReport({
			depRef: 'pkg:maven/org.apache.commons/commons-lang3@3.16.0',
			fixedIn: ['pkg:maven/org.apache.commons/commons-lang3@3.17.0'],
		})

		/**
		 * Creates a multi-project Gradle layout and wires the catalog to it.
		 * @returns {{rootBuild: string, appBuild: string, tomlPath: string, cleanup: function}}
		 */
		function createMultiProject() {
			const { dir, cleanup } = createTempDir({
				'build.gradle': '// root',
				'app/build.gradle': '// app',
				'gradle/libs.versions.toml': CATALOG,
			})
			const rootBuild = path.join(dir, 'build.gradle')
			const appBuild = path.join(dir, 'app', 'build.gradle')
			findNearestBuildFileStub.returns(rootBuild)
			discoverGradleSubprojectsStub.resolves([rootBuild, appBuild])
			matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'gradle' }) })
			return { rootBuild, appBuild, tomlPath: path.join(dir, 'gradle', 'libs.versions.toml'), cleanup }
		}

		test('analyzes every project in the build and applies subproject remediations to the catalog', async () => {
			const { rootBuild, appBuild, tomlPath, cleanup } = createMultiProject()
			try {
				requestStackStub.callsFake(async (_provider, manifestPath) =>
					manifestPath === appBuild ? SUBPROJECT_REPORT : { providers: {} })

				const result = await runRemediation(tomlPath, {})

				expect(requestStackStub.callCount).to.equal(2)
				expect(requestStackStub.firstCall.args[1]).to.equal(rootBuild)
				expect(result.remediations.map(r => r.artifactId)).to.deep.equal(['commons-lang3'])
				expect(fs.readFileSync(tomlPath, 'utf-8')).to.include('3.17.0')
			} finally {
				cleanup()
			}
		})

		test('reports a dependency found in several projects once', async () => {
			const { tomlPath, cleanup } = createMultiProject()
			try {
				requestStackStub.resolves(SUBPROJECT_REPORT)

				const result = await runRemediation(tomlPath, { dryRun: true })

				expect(result.remediations).to.have.lengthOf(1)
				expect(result.groups).to.have.lengthOf(1)
			} finally {
				cleanup()
			}
		})

		test('reports a subproject dependency absent from the catalog as skipped', async () => {
			const { tomlPath, cleanup } = createMultiProject()
			try {
				requestStackStub.resolves(buildMultiDepReport([
					{ depRef: 'pkg:maven/org.apache.commons/commons-lang3@3.16.0', fixedIn: ['pkg:maven/org.apache.commons/commons-lang3@3.17.0'], issueId: 'CVE-2024-0001' },
					{ depRef: 'pkg:maven/com.example/direct-dep@1.0', fixedIn: ['pkg:maven/com.example/direct-dep@1.1'], issueId: 'CVE-2024-0002' },
				]))

				const result = await runRemediation(tomlPath, { dryRun: true })

				expect(result.skipped).to.deep.include({
					groupId: 'com.example',
					artifactId: 'direct-dep',
					newVersion: '1.1',
					reason: 'Dependency not declared in the version catalog',
				})
			} finally {
				cleanup()
			}
		})

		test('falls back to the catalog itself when no Gradle build is discovered', async () => {
			const { dir, cleanup } = createTempDir({ 'gradle/libs.versions.toml': CATALOG })
			try {
				const tomlPath = path.join(dir, 'gradle', 'libs.versions.toml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'gradle' }) })
				requestStackStub.resolves(SUBPROJECT_REPORT)

				const result = await runRemediation(tomlPath, { dryRun: true })

				expect(requestStackStub.callCount).to.equal(1)
				expect(requestStackStub.firstCall.args[1]).to.equal(tomlPath)
				expect(result.remediations).to.have.lengthOf(1)
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
				expect(result.groups).to.deep.equal([])
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
				expect(result.groups).to.deep.equal([])
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

	suite('groups', () => {
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

		/** Single dep produces one group with divergent=false. */
		test('single dep produces one group', async () => {
			const { dir, cleanup } = createTempDir({ 'pom.xml': SAMPLE_POM })
			try {
				const pomPath = path.join(dir, 'pom.xml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'maven' }) })
				requestStackStub.resolves(buildAnalysisReport())

				const result = await runRemediation(pomPath, { dryRun: true })

				expect(result.groups).to.have.lengthOf(1)
				const group = result.groups[0]
				expect(group.changeKey).to.equal(`mvn:direct:${pomPath}:org.apache.commons:commons-text`)
				expect(group.appliedVersion).to.equal('1.10.0')
				expect(group.divergent).to.equal(false)
				expect(group.remediations).to.have.lengthOf(1)
				expect(group.edit.path).to.equal(pomPath)
				expect(group.edit.after).to.include('1.10.0')
			} finally {
				cleanup()
			}
		})

		/** Two independent deps produce two groups with distinct changeKeys. */
		test('two separate deps produce distinct groups with isolated content', async () => {
			const { dir, cleanup } = createTempDir({ 'pom.xml': MULTI_POM })
			try {
				const pomPath = path.join(dir, 'pom.xml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'maven' }) })
				requestStackStub.resolves(buildMultiDepReport([
					{ depRef: 'pkg:maven/org.apache.commons/commons-text@1.9', fixedIn: ['pkg:maven/org.apache.commons/commons-text@1.10.0'], issueId: 'CVE-2022-42889' },
					{ depRef: 'pkg:maven/com.fasterxml.jackson.core/jackson-core@2.14.0', fixedIn: ['pkg:maven/com.fasterxml.jackson.core/jackson-core@2.15.0'], issueId: 'CVE-2020-1000' },
				]))

				const result = await runRemediation(pomPath, { dryRun: true })

				expect(result.groups).to.have.lengthOf(2)
				const textGroup = result.groups.find(g => g.remediations[0].artifactId === 'commons-text')
				const jacksonGroup = result.groups.find(g => g.remediations[0].artifactId === 'jackson-core')

				expect(textGroup.changeKey).to.not.equal(jacksonGroup.changeKey)
				expect(textGroup.divergent).to.equal(false)
				expect(jacksonGroup.divergent).to.equal(false)

				// commons-text's isolated content bumps ONLY commons-text
				expect(textGroup.edit.after).to.include('1.10.0')
				expect(textGroup.edit.after).to.include('2.14.0')
				expect(textGroup.edit.after).to.not.include('2.15.0')

				expect(fs.readFileSync(pomPath, 'utf-8')).to.equal(MULTI_POM)
			} finally {
				cleanup()
			}
		})

		/** Two deps sharing one ${property} collapse to one group. */
		test('two deps sharing a maven property form one group', async () => {
			const { dir, cleanup } = createTempDir({ 'pom.xml': SHARED_PROP_POM })
			try {
				const pomPath = path.join(dir, 'pom.xml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'maven' }) })
				requestStackStub.resolves(buildMultiDepReport([
					{ depRef: 'pkg:maven/org.apache.commons/commons-text@1.9', fixedIn: ['pkg:maven/org.apache.commons/commons-text@1.10.0'], issueId: 'CVE-2022-42889' },
					{ depRef: 'pkg:maven/org.apache.commons/commons-lang3@1.9', fixedIn: ['pkg:maven/org.apache.commons/commons-lang3@1.10.0'], issueId: 'CVE-2021-2000' },
				]))

				const result = await runRemediation(pomPath, { dryRun: true })

				expect(result.groups).to.have.lengthOf(1)
				const group = result.groups[0]
				expect(group.changeKey).to.equal(`mvn:prop:${pomPath}:commons.version`)
				expect(group.appliedVersion).to.equal('1.10.0')
				expect(group.remediations).to.have.lengthOf(2)
				expect(group.divergent).to.equal(false)
				expect(group.edit.after).to.include('<commons.version>1.10.0</commons.version>')
			} finally {
				cleanup()
			}
		})

		/** Conflicting versions within a group resolve to highest by default. */
		test('conflicting versions resolve to highest, group marked divergent', async () => {
			const { dir, cleanup } = createTempDir({ 'pom.xml': SHARED_PROP_POM })
			try {
				const pomPath = path.join(dir, 'pom.xml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'maven' }) })
				requestStackStub.resolves(buildMultiDepReport([
					{ depRef: 'pkg:maven/org.apache.commons/commons-text@1.9', fixedIn: ['pkg:maven/org.apache.commons/commons-text@1.10.0'], issueId: 'CVE-2022-42889' },
					{ depRef: 'pkg:maven/org.apache.commons/commons-lang3@1.9', fixedIn: ['pkg:maven/org.apache.commons/commons-lang3@1.12.0'], issueId: 'CVE-2021-2000' },
				]))

				const result = await runRemediation(pomPath, { dryRun: true })

				expect(result.groups).to.have.lengthOf(1)
				const group = result.groups[0]
				expect(group.appliedVersion).to.equal('1.12.0')
				expect(group.divergent).to.equal(true)
				expect(group.edit.after).to.include('<commons.version>1.12.0</commons.version>')

				// Individual remediations retain their original fixedInVersion
				const text = group.remediations.find(r => r.artifactId === 'commons-text')
				const lang3 = group.remediations.find(r => r.artifactId === 'commons-lang3')
				expect(text.fixedInVersion).to.equal('1.10.0')
				expect(lang3.fixedInVersion).to.equal('1.12.0')
			} finally {
				cleanup()
			}
		})

		/** Custom conflict resolution function overrides the default policy. */
		test('custom conflictResolution function is used', async () => {
			const { dir, cleanup } = createTempDir({ 'pom.xml': SHARED_PROP_POM })
			try {
				const pomPath = path.join(dir, 'pom.xml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'maven' }) })
				requestStackStub.resolves(buildMultiDepReport([
					{ depRef: 'pkg:maven/org.apache.commons/commons-text@1.9', fixedIn: ['pkg:maven/org.apache.commons/commons-text@1.10.0'], issueId: 'CVE-2022-42889' },
					{ depRef: 'pkg:maven/org.apache.commons/commons-lang3@1.9', fixedIn: ['pkg:maven/org.apache.commons/commons-lang3@1.12.0'], issueId: 'CVE-2021-2000' },
				]))

				// Custom policy: always pick lowest version
				const lowest = (versions) => versions.sort()[0]
				const result = await runRemediation(pomPath, { dryRun: true, conflictResolution: lowest })

				expect(result.groups[0].appliedVersion).to.equal('1.10.0')
				expect(result.groups[0].divergent).to.equal(true)
				expect(result.groups[0].edit.after).to.include('<commons.version>1.10.0</commons.version>')
			} finally {
				cleanup()
			}
		})

		/** Function conflict resolution policy picks the first version encountered. */
		test('conflictResolution function can pick first version', async () => {
			const { dir, cleanup } = createTempDir({ 'pom.xml': SHARED_PROP_POM })
			try {
				const pomPath = path.join(dir, 'pom.xml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'maven' }) })
				requestStackStub.resolves(buildMultiDepReport([
					{ depRef: 'pkg:maven/org.apache.commons/commons-text@1.9', fixedIn: ['pkg:maven/org.apache.commons/commons-text@1.10.0'], issueId: 'CVE-2022-42889' },
					{ depRef: 'pkg:maven/org.apache.commons/commons-lang3@1.9', fixedIn: ['pkg:maven/org.apache.commons/commons-lang3@1.12.0'], issueId: 'CVE-2021-2000' },
				]))

				const first = (versions) => versions[0]
				const result = await runRemediation(pomPath, { dryRun: true, conflictResolution: first })

				// extractRemediations sorts by purl, so commons-lang3 comes first
				expect(result.groups[0].appliedVersion).to.equal('1.12.0')
			} finally {
				cleanup()
			}
		})

		/** Transitive deps (not in manifest) are excluded from groups and reported in skipped. */
		test('transitive deps go to skipped, not groups', async () => {
			const { dir, cleanup } = createTempDir({ 'pom.xml': SAMPLE_POM })
			try {
				const pomPath = path.join(dir, 'pom.xml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'maven' }) })
				requestStackStub.resolves(buildMultiDepReport([
					{ depRef: 'pkg:maven/org.apache.commons/commons-text@1.9', fixedIn: ['pkg:maven/org.apache.commons/commons-text@1.10.0'], issueId: 'CVE-2022-42889' },
					{ depRef: 'pkg:maven/com.transitive/deep-lib@1.0', fixedIn: ['pkg:maven/com.transitive/deep-lib@1.1'], issueId: 'CVE-2023-9999' },
				]))

				const result = await runRemediation(pomPath, { dryRun: true })

				expect(result.groups).to.have.lengthOf(1)
				expect(result.remediations).to.have.lengthOf(1)
				expect(result.remediations[0].artifactId).to.equal('commons-text')
				expect(result.skipped).to.deep.include({
					groupId: 'com.transitive',
					artifactId: 'deep-lib',
					newVersion: '1.1',
					reason: 'Dependency not directly declared in the manifest',
				})
			} finally {
				cleanup()
			}
		})

		/** Groups across multiple manifests in a directory. */
		test('groups span multiple manifests independently', async () => {
			const { dir, cleanup } = createTempDir({
				'module-a/pom.xml': SAMPLE_POM,
				'module-b/libs.versions.toml': SAMPLE_TOML,
			})
			try {
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'maven' }) })
				requestStackStub.onFirstCall().resolves(buildAnalysisReport())
				requestStackStub.onSecondCall().resolves(buildAnalysisReport({
					depRef: 'pkg:maven/com.fasterxml.jackson.core/jackson-core@2.14.0',
					fixedIn: ['pkg:maven/com.fasterxml.jackson.core/jackson-core@2.15.0'],
				}))

				const result = await runRemediation(dir, { dryRun: true })

				expect(result.groups).to.have.lengthOf(2)
				const pomGroup = result.groups.find(g => g.edit.path.endsWith('pom.xml'))
				const tomlGroup = result.groups.find(g => g.edit.path.endsWith('libs.versions.toml'))
				expect(pomGroup).to.not.be.undefined
				expect(tomlGroup).to.not.be.undefined
				expect(pomGroup.changeKey).to.not.equal(tomlGroup.changeKey)
			} finally {
				cleanup()
			}
		})

		/** Flat remediations is equivalent to groups.flatMap(g => g.remediations). */
		test('flat remediations equals groups.flatMap(g => g.remediations)', async () => {
			const { dir, cleanup } = createTempDir({ 'pom.xml': MULTI_POM })
			try {
				const pomPath = path.join(dir, 'pom.xml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'maven' }) })
				requestStackStub.resolves(buildMultiDepReport([
					{ depRef: 'pkg:maven/org.apache.commons/commons-text@1.9', fixedIn: ['pkg:maven/org.apache.commons/commons-text@1.10.0'], issueId: 'CVE-2022-42889' },
					{ depRef: 'pkg:maven/com.fasterxml.jackson.core/jackson-core@2.14.0', fixedIn: ['pkg:maven/com.fasterxml.jackson.core/jackson-core@2.15.0'], issueId: 'CVE-2020-1000' },
				]))

				const result = await runRemediation(pomPath, { dryRun: true })

				const fromGroups = result.groups.flatMap(g => g.remediations)
				expect(result.remediations).to.deep.equal(fromGroups)
			} finally {
				cleanup()
			}
		})

		/** TOML: two deps sharing a version.ref with conflicting targets resolve correctly. */
		test('TOML shared version.ref with conflicting targets resolves to highest', async () => {
			const SHARED_TOML = `[versions]
jackson = "2.14.0"

[libraries]
jackson-core = { module = "com.fasterxml.jackson.core:jackson-core", version.ref = "jackson" }
jackson-databind = { module = "com.fasterxml.jackson.core:jackson-databind", version.ref = "jackson" }
`
			const { dir, cleanup } = createTempDir({ 'libs.versions.toml': SHARED_TOML })
			try {
				const tomlPath = path.join(dir, 'libs.versions.toml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'gradle' }) })
				requestStackStub.resolves(buildMultiDepReport([
					{ depRef: 'pkg:maven/com.fasterxml.jackson.core/jackson-core@2.14.0', fixedIn: ['pkg:maven/com.fasterxml.jackson.core/jackson-core@2.15.0'], issueId: 'CVE-2020-1000' },
					{ depRef: 'pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.14.0', fixedIn: ['pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.17.0'], issueId: 'CVE-2020-2000' },
				]))

				const result = await runRemediation(tomlPath, { dryRun: true })

				expect(result.groups).to.have.lengthOf(1)
				const group = result.groups[0]
				expect(group.appliedVersion).to.equal('2.17.0')
				expect(group.divergent).to.equal(true)
				expect(group.edit.after).to.include('jackson = "2.17.0"')

				const core = group.remediations.find(r => r.artifactId === 'jackson-core')
				const databind = group.remediations.find(r => r.artifactId === 'jackson-databind')
				expect(core.fixedInVersion).to.equal('2.15.0')
				expect(databind.fixedInVersion).to.equal('2.17.0')
			} finally {
				cleanup()
			}
		})

		/** TOML: conflicting targets with apply mode writes the resolved version to disk. */
		test('TOML conflicting targets writes resolved version to disk', async () => {
			const SHARED_TOML = `[versions]
jackson = "2.14.0"

[libraries]
jackson-core = { module = "com.fasterxml.jackson.core:jackson-core", version.ref = "jackson" }
jackson-databind = { module = "com.fasterxml.jackson.core:jackson-databind", version.ref = "jackson" }
`
			const { dir, cleanup } = createTempDir({ 'libs.versions.toml': SHARED_TOML })
			try {
				const tomlPath = path.join(dir, 'libs.versions.toml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'gradle' }) })
				requestStackStub.resolves(buildMultiDepReport([
					{ depRef: 'pkg:maven/com.fasterxml.jackson.core/jackson-core@2.14.0', fixedIn: ['pkg:maven/com.fasterxml.jackson.core/jackson-core@2.15.0'], issueId: 'CVE-2020-1000' },
					{ depRef: 'pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.14.0', fixedIn: ['pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.17.0'], issueId: 'CVE-2020-2000' },
				]))

				const result = await runRemediation(tomlPath, {})

				expect(result.appliedFiles).to.deep.equal([tomlPath])
				const written = fs.readFileSync(tomlPath, 'utf-8')
				expect(written).to.include('jackson = "2.17.0"')
			} finally {
				cleanup()
			}
		})

		/** TOML: two deps sharing a version.ref form one group. */
		test('TOML deps sharing version.ref form one group', async () => {
			const SHARED_TOML = `[versions]
jackson = "2.14.0"

[libraries]
jackson-core = { module = "com.fasterxml.jackson.core:jackson-core", version.ref = "jackson" }
jackson-databind = { module = "com.fasterxml.jackson.core:jackson-databind", version.ref = "jackson" }
`
			const { dir, cleanup } = createTempDir({ 'libs.versions.toml': SHARED_TOML })
			try {
				const tomlPath = path.join(dir, 'libs.versions.toml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'gradle' }) })
				requestStackStub.resolves(buildMultiDepReport([
					{ depRef: 'pkg:maven/com.fasterxml.jackson.core/jackson-core@2.14.0', fixedIn: ['pkg:maven/com.fasterxml.jackson.core/jackson-core@2.15.0'], issueId: 'CVE-2020-1000' },
					{ depRef: 'pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.14.0', fixedIn: ['pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.15.0'], issueId: 'CVE-2020-2000' },
				]))

				const result = await runRemediation(tomlPath, { dryRun: true })

				expect(result.groups).to.have.lengthOf(1)
				const group = result.groups[0]
				expect(group.changeKey).to.equal(`toml:ref:${tomlPath}:jackson`)
				expect(group.appliedVersion).to.equal('2.15.0')
				expect(group.remediations).to.have.lengthOf(2)
				expect(group.divergent).to.equal(false)
				expect(group.edit.after).to.include('2.15.0')
			} finally {
				cleanup()
			}
		})
	})

	suite('exclude filter', () => {
		const EXCLUDE_POM = `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-text</artifactId>
      <version>1.9</version>
    </dependency>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>3.9</version>
    </dependency>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-core</artifactId>
      <version>2.14.0</version>
    </dependency>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.0</version>
    </dependency>
  </dependencies>
</project>`

		const COMMONS_TEXT = { depRef: 'pkg:maven/org.apache.commons/commons-text@1.9', fixedIn: ['pkg:maven/org.apache.commons/commons-text@1.10.0'], issueId: 'CVE-2022-42889' }
		const JACKSON_CORE = { depRef: 'pkg:maven/com.fasterxml.jackson.core/jackson-core@2.14.0', fixedIn: ['pkg:maven/com.fasterxml.jackson.core/jackson-core@2.15.0'], issueId: 'CVE-2020-1000' }
		const LOG4J = { depRef: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0', fixedIn: ['pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1'], issueId: 'CVE-2021-44228' }

		/** An excluded purl (matched without its @version) is absent from the result. */
		test('excluded purl is absent from result.remediations', async () => {
			const { dir, cleanup } = createTempDir({ 'pom.xml': SAMPLE_POM })
			try {
				const pomPath = path.join(dir, 'pom.xml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'maven' }) })
				requestStackStub.resolves(buildMultiDepReport([COMMONS_TEXT]))

				const result = await runRemediation(pomPath, { dryRun: true, exclude: ['pkg:maven/org.apache.commons/commons-text'] })

				expect(result.remediations).to.have.lengthOf(0)
				expect(result.remediations.map(r => r.artifactId)).to.not.include('commons-text')
			} finally {
				cleanup()
			}
		})

		/** Non-excluded purls survive even when an exclude list is present. */
		test('non-excluded purls are present when an exclude list is non-empty', async () => {
			const { dir, cleanup } = createTempDir({ 'pom.xml': EXCLUDE_POM })
			try {
				const pomPath = path.join(dir, 'pom.xml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'maven' }) })
				requestStackStub.resolves(buildMultiDepReport([COMMONS_TEXT, JACKSON_CORE]))

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
			const { dir, cleanup } = createTempDir({ 'pom.xml': EXCLUDE_POM })
			try {
				const pomPath = path.join(dir, 'pom.xml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'maven' }) })
				requestStackStub.resolves(buildMultiDepReport([COMMONS_TEXT, JACKSON_CORE]))

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
			const { dir, cleanup } = createTempDir({ 'pom.xml': EXCLUDE_POM })
			try {
				const pomPath = path.join(dir, 'pom.xml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'maven' }) })
				requestStackStub.resolves(buildMultiDepReport([COMMONS_TEXT, JACKSON_CORE, LOG4J]))

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
			const { dir, cleanup } = createTempDir({ 'pom.xml': EXCLUDE_POM })
			try {
				const pomPath = path.join(dir, 'pom.xml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'maven' }) })
				requestStackStub.resolves(buildMultiDepReport([
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
			const { dir, cleanup } = createTempDir({ 'pom.xml': EXCLUDE_POM })
			try {
				const pomPath = path.join(dir, 'pom.xml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'maven' }) })
				requestStackStub.resolves(buildMultiDepReport([COMMONS_TEXT, JACKSON_CORE]))

				const result = await runRemediation(pomPath, { dryRun: true, exclude: ['pkg:maven/org.apache.commons/commons-*'] })

				const artifacts = result.remediations.map(r => r.artifactId)
				expect(artifacts).to.deep.equal(['jackson-core'])
			} finally {
				cleanup()
			}
		})

		/** A `**` globstar crosses `/` segments, excluding a whole ecosystem. */
		test('globstar pattern excludes an entire ecosystem across segments', async () => {
			const { dir, cleanup } = createTempDir({ 'pom.xml': EXCLUDE_POM })
			try {
				const pomPath = path.join(dir, 'pom.xml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'maven' }) })
				requestStackStub.resolves(buildMultiDepReport([
					COMMONS_TEXT,
					JACKSON_CORE,
					LOG4J,
				]))

				// `**` crosses the namespace/name boundary; `*` would not.
				// Exclude all maven deps — nothing should survive since all are maven.
				const result = await runRemediation(pomPath, { dryRun: true, exclude: ['pkg:maven/**'] })

				expect(result.remediations).to.have.lengthOf(0)
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
				requestStackStub.resolves(buildMultiDepReport([COMMONS_TEXT]))

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
				requestStackStub.resolves(buildMultiDepReport([
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
				expect(result.skipped[0].reason).to.equal('Shares a Maven property with excluded dependency pkg:maven/org.apache.commons/commons-text')
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
				requestStackStub.resolves(buildMultiDepReport([
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

		/** Excluded dep with no remediation still blocks a co-located retained dep. */
		test('shared property blocks retained dep even when excluded dep has no remediation', async () => {
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
				// Only commons-text has a remediation; commons-lang3 has no vulnerability at all.
				requestStackStub.resolves(buildMultiDepReport([COMMONS_TEXT]))

				const result = await runRemediation(pomPath, {
					dryRun: true,
					exclude: ['pkg:maven/org.apache.commons/commons-lang3'],
				})

				// commons-text's fix would bump ${commons.version}, also upgrading
				// the excluded commons-lang3. Must be blocked.
				expect(result.remediations).to.have.lengthOf(0)
				expect(result.skipped).to.have.lengthOf(1)
				expect(result.skipped[0].artifactId).to.equal('commons-text')
				expect(result.skipped[0].reason).to.include('commons-lang3')
				expect(fs.readFileSync(pomPath, 'utf-8')).to.equal(SHARED_PROP_POM)
			} finally {
				cleanup()
			}
		})

		/** Percent-encoded artifactId in the exclude pattern is decoded before matching. */
		test('percent-encoded exclude pattern matches decoded purl', async () => {
			const { dir, cleanup } = createTempDir({ 'pom.xml': EXCLUDE_POM })
			try {
				const pomPath = path.join(dir, 'pom.xml')
				matchStub.returns({ provideStack: stub().resolves({ content: '{}', contentType: 'application/json', ecosystem: 'maven' }) })
				requestStackStub.resolves(buildMultiDepReport([
					{ depRef: 'pkg:maven/org.apache.commons/commons-text@1.9', fixedIn: ['pkg:maven/org.apache.commons/commons-text@1.10.0'], issueId: 'CVE-2022-42889' },
					JACKSON_CORE,
				]))

				// Exclude pattern uses percent-encoded artifactId (%2D = hyphen)
				const withEncoded = await runRemediation(pomPath, { dryRun: true, exclude: ['pkg:maven/org.apache.commons/commons%2Dtext'] })
				const withDecoded = await runRemediation(pomPath, { dryRun: true, exclude: ['pkg:maven/org.apache.commons/commons-text'] })

				expect(withEncoded.remediations.map(r => r.artifactId)).to.deep.equal(['jackson-core'])
				expect(withDecoded.remediations.map(r => r.artifactId)).to.deep.equal(['jackson-core'])
			} finally {
				cleanup()
			}
		})
	})

	suite('exclude matcher — unit tests', () => {
		let compileExcludeMatcher

		setup(async () => {
			const mod = await esmock('../src/remediate.js', {
				'../src/analysis.js': { default: { requestStack: stub() } },
				'../src/provider.js': { match: stub(), availableProviders: [] },
				'../src/index.js': { selectTrustifyDABackend: () => 'https://da.example.com' },
			})
			compileExcludeMatcher = mod.compileExcludeMatcher
		})

		test('decodes percent-encoded npm scope in pattern', () => {
			const matcher = compileExcludeMatcher('pkg:npm/%40babel/traverse')
			expect(matcher('pkg:npm/@babel/traverse')).to.equal(true)
			expect(matcher('pkg:npm/@babel/core')).to.equal(false)
		})

		test('** crosses segments, * does not', () => {
			const globstar = compileExcludeMatcher('pkg:maven/**')
			const star = compileExcludeMatcher('pkg:maven/*')
			expect(globstar('pkg:maven/com.example/foo')).to.equal(true)
			expect(star('pkg:maven/com.example/foo')).to.equal(false)
			expect(star('pkg:maven/single-segment')).to.equal(true)
		})

		test('type is case-insensitive', () => {
			const matcher = compileExcludeMatcher('pkg:NPM/@scope/name')
			expect(matcher('pkg:npm/@scope/name')).to.equal(true)
		})
	})

	suite('compareVersions — prerelease behavior', () => {
		let compareVersions

		setup(async () => {
			const mod = await import('../src/remediation.js')
			compareVersions = mod.compareVersions
		})

		test('prerelease sorts above its stable release (current behavior)', () => {
			expect(compareVersions('2.0.0-rc1', '2.0.0')).to.be.greaterThan(0)
		})

		test('higher stable version sorts above lower prerelease', () => {
			expect(compareVersions('2.1.0', '2.0.0-rc1')).to.be.greaterThan(0)
		})
	})
})
