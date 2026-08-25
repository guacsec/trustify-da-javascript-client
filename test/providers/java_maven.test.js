import crypto from 'node:crypto'
import fs from 'node:fs'
import os, { platform } from 'node:os'
import path from 'node:path'

import { expect } from 'chai'
import esmock from 'esmock';
import { spy, useFakeTimers } from "sinon";
import which from 'which';

import Java_maven from '../../src/providers/java_maven.js'

let clock

async function mockProvider(cwd) {

	const mockInvokeCommand = () => {
		return '';
	};

	const mockGitRootDir = (cwd) => {
		return cwd;
	}

	const mockFs = {
		mkdtempSync: (pathName) => pathName,
		readFileSync: (filePath) => {
			const output = path.join(cwd, path.basename(filePath));
			return fs.readFileSync(output);
		},
		// Mirror readFileSync's path remapping so Maven hash computation reads from
		// the scenario fixture dir (which has no jars) rather than the real ~/.m2.
		// The remapped jar path never exists, so the stream errors and the hash is
		// deterministically omitted — matching the expected SBOMs on any machine.
		createReadStream: (filePath) => {
			const output = path.join(cwd, path.basename(filePath));
			return fs.createReadStream(output);
		},
		rmSync: () => {}
	}

	return esmock('../../src/providers/java_maven.js', {
		fs: mockFs,
		'../../src/providers/base_java.js': await esmock('../../src/providers/base_java.js', {
			'../../src/tools.js': {
				invokeCommand: mockInvokeCommand,
				getGitRootDir: mockGitRootDir
			}
		})
	});
}

async function createMockProvider(testPath) {
	const Java_maven = await mockProvider(testPath);
	return new Java_maven();
}

const mvnPath = await which('mvn');
suite('testing the java-maven data provider', async () => {
	// Fake only Date (for deterministic SBOM timestamps); faking setImmediate/timers
	// would deadlock the streaming SHA-256 hash reader's `for await` on fs streams.
	suiteSetup(() => clock = useFakeTimers({ now: new Date('2023-08-07T00:00:00.000Z'), toFake: ['Date'] }));
	suiteTeardown(() => clock.restore());

	[
		{name: 'pom.xml', expected: true},
		{name: 'some_other.file', expected: false}
	].forEach(testCase => {
		test(`verify isSupported returns ${testCase.expected} for ${testCase.name}`, () => {
			let javaMvnProvider = new Java_maven()
			expect(javaMvnProvider.isSupported(testCase.name)).to.equal(testCase.expected)
		})
	});

	[
		{mvnPath: mvnPath, preferWrapper: false},
		{mvnPath: mvnPath, preferWrapper: true},
		{mvnPath: 'mvn', preferWrapper: false},
		{mvnPath: 'mvn', preferWrapper: true},
	].forEach(testCase => {
		test(`verify tool selection with "${testCase.mvnPath}" and${testCase.preferWrapper ? ' ' : ' not '}preferring wrapper`, () => {
			let javaMvnProvider = new Java_maven()
			expect(javaMvnProvider.selectToolBinary(`test/providers/tst_manifests/maven/pom_with_mvn_wrapper/pom.xml`, {
				'TRUSTIFY_DA_PREFER_MVNW': testCase.preferWrapper.toString(),
				'TRUSTIFY_DA_MVN_PATH': testCase.mvnPath,
			})).to.eq(testCase.preferWrapper ?
				path.resolve(`test/providers/tst_manifests/maven/pom_with_mvn_wrapper/mvnw`) + (platform === 'win32' ? '.cmd' : '')
				: testCase.mvnPath)
		}).timeout(10000)
	});

	[
		"poms_deps_with_2_ignore_long",
		"pom_deps_with_ignore_on_artifact",
		"pom_deps_with_ignore_on_dependency",
		"pom_deps_with_ignore_on_group",
		"pom_deps_with_ignore_on_version",
		"pom_deps_with_ignore_version_from_property",
		"pom_deps_with_ignore_on_wrong",
		"pom_deps_with_no_ignore",
		"poms_deps_with_ignore_long",
		"poms_deps_with_no_ignore_long",
		"pom_deps_with_no_ignore_common_paths",
		"pom_deps_with_version_range"
	].forEach(testCase => {
		let scenario = testCase.replace('pom_deps_', '').replaceAll('_', ' ')

		test(`verify maven data provided for stack analysis with scenario ${scenario}`, async () => {
			// load the expected graph for the scenario
			let expectedSbom = fs.readFileSync(`test/providers/tst_manifests/maven/${testCase}/stack_analysis_expected_sbom.json`,).toString().trim()
			// let dependencyTreeTextContent = fs.readFileSync(`test/providers/tst_manifests/maven/${testCase}/dep-tree.txt`,).toString()
			expectedSbom = JSON.stringify(JSON.parse(expectedSbom),null, 4)
			let javaMvnProvider = await createMockProvider(`test/providers/tst_manifests/maven/${testCase}`);
			// invoke sut stack analysis for scenario manifest
			let providedDataForStack = await javaMvnProvider.provideStack(`test/providers/tst_manifests/maven/${testCase}/pom.xml`)
			// verify returned data matches expectation
			let beautifiedOutput = JSON.stringify(JSON.parse(providedDataForStack.content),null, 4);
			expect(beautifiedOutput).to.deep.equal(expectedSbom)

		// these test cases takes ~2500-2700 ms each pr >10000 in CI (for the first test-case)
		}).timeout(process.env.GITHUB_ACTIONS ? 40000 : 10000)

		test(`verify maven data provided for component analysis with scenario ${scenario}`, async () => {
			// load the expected list for the scenario
			let expectedSbom = fs.readFileSync(`test/providers/tst_manifests/maven/${testCase}/component_analysis_expected_sbom.json`,).toString().trim()
			// read target manifest file
			expectedSbom = JSON.stringify(JSON.parse(expectedSbom))
			let javaMvnProvider = await createMockProvider(`test/providers/tst_manifests/maven/${testCase}`);
			// invoke sut component analysis for scenario manifest
			let providedDataForStack = javaMvnProvider.provideComponent(`test/providers/tst_manifests/maven/${testCase}/pom.xml`)
			// verify returned data matches expectation
			expect(providedDataForStack).to.deep.equal({
				ecosystem: 'maven',
				contentType: 'application/vnd.cyclonedx+json',
				content: expectedSbom
			})
			// these test cases takes ~1400-2000 ms each pr >10000 in CI (for the first test-case)
		}).timeout(process.env.GITHUB_ACTIONS ? 15000 : 5000)
		// these test cases takes ~1400-2000 ms each pr >10000 in CI (for the first test-case)

	})
});

suite('testing the java-maven data provider with modules', () => {
	suiteSetup(() => clock = useFakeTimers({ now: new Date('2023-08-07T00:00:00.000Z'), toFake: ['Date'] }));
	suiteTeardown(() => clock.restore());
	[
		"pom_with_one_module",
		"pom_with_multiple_modules"

	].forEach(testCase => {
		let scenario = testCase.replaceAll('_', ' ')
		test(`verify maven data provided for component analysis using path for scenario ${scenario}`, async () => {
			// load the expected list for the scenario
			let expectedSbom = fs.readFileSync(`test/providers/tst_manifests/maven/${testCase}/component_analysis_expected_sbom.json`,).toString().trim()
			// read target manifest file
			expectedSbom = JSON.stringify(JSON.parse(expectedSbom))
			let javaMvnProvider = await createMockProvider(`test/providers/tst_manifests/maven/${testCase}`);
			// invoke sut component analysis for scenario manifest
			let provideDataForComponent = javaMvnProvider.provideComponent(`test/providers/tst_manifests/maven/${testCase}/pom.xml`, {})
			// verify returned data matches expectation
			expect(provideDataForComponent).to.deep.equal({
				ecosystem: 'maven',
				contentType: 'application/vnd.cyclonedx+json',
				content: expectedSbom
			})
			// these test cases takes ~2500-2700 ms each pr >10000 in CI (for the first test-case)
		}).timeout(process.env.GITHUB_ACTIONS ? 40000 : 10000)

		// these test cases takes ~1400-2000 ms each pr >10000 in CI (for the first test-case)

	})
});

suite('testing the java-maven version parsing in getDependencies', () => {
	suiteSetup(() => clock = useFakeTimers({ now: new Date('2023-08-07T00:00:00.000Z'), toFake: ['Date'] }));
	suiteTeardown(() => clock.restore());
	test('verify version parsing works correctly', async () => {
		const testCase = 'pom_deps_with_ignore_version_from_property';
		const javaMvnProvider = await createMockProvider(`test/providers/tst_manifests/maven/${testCase}`);

		// Use provideComponent to test the version parsing through the public interface
		const result = javaMvnProvider.provideComponent(`test/providers/tst_manifests/maven/${testCase}/pom.xml`);
		const sbom = JSON.parse(result.content);

		// Find the BouncyCastle dependency in the SBOM
		const bouncyCastleDependency = sbom.dependencies.find(dep =>
			dep.ref === 'pkg:maven/org.bouncycastle/bcprov-jdk18on@1.80'
		);

		expect(bouncyCastleDependency).to.exist;
		expect(bouncyCastleDependency.ref).to.equal('pkg:maven/org.bouncycastle/bcprov-jdk18on@1.80');
	});
});

suite('testing the java-maven SHA-256 hash computation', () => {
	let tmpM2Repo
	const jarContent = Buffer.from('mock-jar-content-for-testing')
	const expectedDigest = crypto.createHash('sha256').update(jarContent).digest('hex')

	suiteSetup(() => {
		tmpM2Repo = fs.mkdtempSync(path.join(os.tmpdir(), 'trustify_da_m2_test_'))
		// Create a mock .m2 directory structure with a jar file
		const jarDir = path.join(tmpM2Repo, 'log4j', 'log4j', '1.2.17')
		fs.mkdirSync(jarDir, { recursive: true })
		fs.writeFileSync(path.join(jarDir, 'log4j-1.2.17.jar'), jarContent)
	})

	suiteTeardown(() => {
		fs.rmSync(tmpM2Repo, { recursive: true, force: true })
	})

	/** Verifies that SHA-256 hashes are computed from jar files in the local .m2 repository. */
	test('verify _buildMavenHashMap computes SHA-256 from jar files', async () => {
		// Given a dependency tree with a dependency whose jar exists in the mock .m2 repo
		const provider = new Java_maven()
		const depTree = 'com.example:root:jar:1.0.0\n\\- log4j:log4j:jar:1.2.17:compile\n'

		// When building the hash map using the mock .m2 repo
		const hashMap = await provider._buildMavenHashMap(depTree, { 'TRUSTIFY_DA_MVN_REPO': tmpM2Repo })

		// Then the hash map contains the correct SHA-256 digest for log4j
		const purl = 'pkg:maven/log4j/log4j@1.2.17'
		expect(hashMap.has(purl)).to.equal(true)
		expect(hashMap.get(purl)).to.deep.equal([{ alg: 'SHA-256', content: expectedDigest }])
	})

	/** Verifies that missing jar files result in omitted hashes rather than errors. */
	test('verify _buildMavenHashMap omits hash when jar file is not in cache', async () => {
		// Given a dependency tree referencing an artifact not in the mock repo
		const provider = new Java_maven()
		const depTree = 'com.example:root:jar:1.0.0\n\\- org.missing:artifact:jar:1.0.0:compile\n'

		// When building the hash map
		const hashMap = await provider._buildMavenHashMap(depTree, { 'TRUSTIFY_DA_MVN_REPO': tmpM2Repo })

		// Then the hash map is empty — no error thrown
		expect(hashMap.size).to.equal(0)
	})

	/** Verifies that custom Maven repository path via TRUSTIFY_DA_MVN_REPO is respected. */
	test('verify _buildMavenHashMap uses custom TRUSTIFY_DA_MVN_REPO path', async () => {
		// Given the env var points to our mock .m2 repo
		const provider = new Java_maven()
		const depTree = 'com.example:root:jar:1.0.0\n\\- log4j:log4j:jar:1.2.17:compile\n'

		// When building hash map with TRUSTIFY_DA_MVN_REPO set via opts
		const hashMap = await provider._buildMavenHashMap(depTree, { 'TRUSTIFY_DA_MVN_REPO': tmpM2Repo })

		// Then hash is found (proving the custom path was used)
		expect(hashMap.has('pkg:maven/log4j/log4j@1.2.17')).to.equal(true)
	})

	/** Verifies that packaging types like 'bundle' are mapped to .jar file extension. */
	test('verify _buildMavenHashMap maps bundle packaging to .jar extension', async () => {
		// Given a mock jar under a groupId that uses 'bundle' packaging in the tree
		const bundleDir = path.join(tmpM2Repo, 'org', 'osgi', 'core', '6.0.0')
		fs.mkdirSync(bundleDir, { recursive: true })
		fs.writeFileSync(path.join(bundleDir, 'core-6.0.0.jar'), jarContent)

		const provider = new Java_maven()
		const depTree = 'com.example:root:jar:1.0.0\n\\- org.osgi:core:bundle:6.0.0:compile\n'

		// When building the hash map
		const hashMap = await provider._buildMavenHashMap(depTree, { 'TRUSTIFY_DA_MVN_REPO': tmpM2Repo })

		// Then the bundle dependency gets a hash (mapped to .jar)
		expect(hashMap.has('pkg:maven/org.osgi/core@6.0.0')).to.equal(true)
		expect(hashMap.get('pkg:maven/org.osgi/core@6.0.0')[0].content).to.equal(expectedDigest)
	})

	/** Verifies that POM-only artifacts are skipped and no hash is computed. */
	test('verify _buildMavenHashMap skips pom packaging type', async () => {
		const provider = new Java_maven()
		const depTree = 'com.example:root:jar:1.0.0\n\\- org.example:bom:pom:1.0.0:compile\n'

		// When building the hash map
		const hashMap = await provider._buildMavenHashMap(depTree, { 'TRUSTIFY_DA_MVN_REPO': tmpM2Repo })

		// Then no hash entry for the pom-only artifact
		expect(hashMap.has('pkg:maven/org.example/bom@1.0.0')).to.equal(false)
	})

	/** Verifies that classified dependencies produce the correct file path with classifier in the filename. */
	test('verify _buildMavenHashMap handles classified dependencies', async () => {
		// Given a jar with classifier in the expected path
		const classifiedDir = path.join(tmpM2Repo, 'io', 'netty', 'netty-transport', '4.1.0')
		fs.mkdirSync(classifiedDir, { recursive: true })
		fs.writeFileSync(path.join(classifiedDir, 'netty-transport-4.1.0-linux-x86_64.jar'), jarContent)

		const provider = new Java_maven()
		const depTree = 'com.example:root:jar:1.0.0\n\\- io.netty:netty-transport:jar:linux-x86_64:4.1.0:compile\n'

		// When building the hash map
		const hashMap = await provider._buildMavenHashMap(depTree, { 'TRUSTIFY_DA_MVN_REPO': tmpM2Repo })

		// Then the classified dependency gets a hash keyed by the mangled PURL
		const purl = 'pkg:maven/io.netty/netty-transport@4.1.0-linux-x86_64'
		expect(hashMap.has(purl)).to.equal(true)
		expect(hashMap.get(purl)[0].content).to.equal(expectedDigest)
	})

	/** Verifies that hashes flow through createSbomFileFromTextFormat into SBOM components. */
	test('verify hashes appear in SBOM components via createSbomFileFromTextFormat', () => {
		// Given a dependency tree and a hash map with an entry
		const clock = useFakeTimers({ now: new Date('2023-08-07T00:00:00.000Z'), toFake: ['Date'] })
		try {
			const provider = new Java_maven()
			const depTree = 'com.example:root:jar:1.0.0\n\\- log4j:log4j:jar:1.2.17:compile'
			const hashMap = new Map()
			hashMap.set('pkg:maven/log4j/log4j@1.2.17', [{ alg: 'SHA-256', content: 'abcdef1234567890' }])

			// When creating the SBOM with the hash map
			const sbomJson = provider.createSbomFileFromTextFormat(
				depTree, [], {},
				'test/providers/tst_manifests/maven/pom_deps_with_no_ignore/pom.xml',
				hashMap
			)
			const sbom = JSON.parse(sbomJson)

			// Then the log4j component includes the hash
			const log4jComponent = sbom.components.find(c => c.name === 'log4j')
			expect(log4jComponent).to.exist
			expect(log4jComponent.hashes).to.deep.equal([{ alg: 'SHA-256', content: 'abcdef1234567890' }])
		} finally {
			clock.restore()
		}
	})

	/** Verifies that lines with empty parts from DEP_REGEX mismatch are skipped without error. */
	test('verify _buildMavenHashMap skips lines with empty parsed fields', async () => {
		const provider = new Java_maven()
		const depTree = 'com.example:root:jar:1.0.0\n\\- :log4j:jar:1.2.17:compile\n\\- log4j::jar:1.2.17:compile\n'

		// When building the hash map with lines that have empty groupId or artifactId
		const hashMap = await provider._buildMavenHashMap(depTree, { 'TRUSTIFY_DA_MVN_REPO': tmpM2Repo })

		// Then the hash map is empty — malformed lines are skipped
		expect(hashMap.size).to.equal(0)
	})

	/**
	 * Verifies that an artifact recurring across dependency-tree branches (as in a
	 * multi-module reactor build) is read and hashed only once — the dedup guard
	 * skips the redundant file read + SHA-256 computation for the already-hashed PURL.
	 */
	test('verify _buildMavenHashMap reads each artifact once despite repeated tree lines', async () => {
		// Given the same resolved artifact listed on three separate tree branches
		const readSpy = spy(fs, 'createReadStream')
		try {
			const provider = new Java_maven()
			const depTree = [
				'com.example:root:jar:1.0.0',
				'+- com.example:module-a:jar:1.0.0:compile',
				'|  \\- log4j:log4j:jar:1.2.17:compile',
				'+- com.example:module-b:jar:1.0.0:compile',
				'|  \\- log4j:log4j:jar:1.2.17:compile',
				'\\- com.example:module-c:jar:1.0.0:compile',
				'   \\- log4j:log4j:jar:1.2.17:compile'
			].join('\n')
			const log4jJar = path.join(tmpM2Repo, 'log4j', 'log4j', '1.2.17', 'log4j-1.2.17.jar')

			// When building the hash map
			const hashMap = await provider._buildMavenHashMap(depTree, { 'TRUSTIFY_DA_MVN_REPO': tmpM2Repo })

			// Then the log4j jar is read exactly once even though it appears three times,
			// and its hash is still present with the correct digest
			const log4jReads = readSpy.getCalls().filter(c => c.args[0] === log4jJar)
			expect(log4jReads.length).to.equal(1)
			expect(hashMap.get('pkg:maven/log4j/log4j@1.2.17')).to.deep.equal([{ alg: 'SHA-256', content: expectedDigest }])
		} finally {
			readSpy.restore()
		}
	})

	/**
	 * Verifies that an incomplete .m2 cache surfaces a summary warning (even
	 * without TRUSTIFY_DA_DEBUG) reporting how many of the attempted artifacts
	 * could not be read, so degraded hash coverage is visible rather than silent.
	 */
	test('verify _buildMavenHashMap warns with a coverage summary when artifacts are missing', async () => {
		// Given a tree with one cached artifact (log4j) and one absent from the mock repo
		const warnSpy = spy(console, 'warn')
		try {
			const provider = new Java_maven()
			const depTree = [
				'com.example:root:pom:1.0.0',
				'+- log4j:log4j:jar:1.2.17:compile',
				'\\- com.example:missing-lib:jar:9.9.9:compile'
			].join('\n')

			// When building the hash map
			const hashMap = await provider._buildMavenHashMap(depTree, { 'TRUSTIFY_DA_MVN_REPO': tmpM2Repo })

			// Then the cached artifact is still hashed, and exactly one summary
			// warning reports the single miss out of the two attempted reads
			expect(hashMap.has('pkg:maven/log4j/log4j@1.2.17')).to.equal(true)
			expect(hashMap.has('pkg:maven/com.example/missing-lib@9.9.9')).to.equal(false)
			expect(warnSpy.callCount).to.equal(1)
			expect(warnSpy.firstCall.args[0]).to.equal(
				'Maven hash: 1 of 2 artifacts could not be read from the local .m2 cache; SBOM will be generated without hashes for those components.'
			)
		} finally {
			warnSpy.restore()
		}
	})

	/** Verifies that no coverage warning is emitted when every attempted artifact is hashed. */
	test('verify _buildMavenHashMap stays silent when all artifacts are hashed', async () => {
		// Given a tree whose only artifact (log4j) exists in the mock repo
		const warnSpy = spy(console, 'warn')
		try {
			const provider = new Java_maven()
			const depTree = 'com.example:root:pom:1.0.0\n\\- log4j:log4j:jar:1.2.17:compile'

			// When building the hash map
			const hashMap = await provider._buildMavenHashMap(depTree, { 'TRUSTIFY_DA_MVN_REPO': tmpM2Repo })

			// Then the artifact is hashed and no coverage warning is emitted
			expect(hashMap.has('pkg:maven/log4j/log4j@1.2.17')).to.equal(true)
			expect(warnSpy.called).to.equal(false)
		} finally {
			warnSpy.restore()
		}
	})

	/**
	 * Verifies that parenthesized (omitted/duplicate) lines are skipped by the
	 * guard itself — before any file I/O — even when the referenced artifact IS
	 * present in the mock .m2 repository. This proves the tree-character-stripping
	 * guard is what filters the line, not an incidentally missing fixture jar.
	 */
	test('verify _buildMavenHashMap skips parenthesized duplicate entries via the guard', async () => {
		// Given the "omitted for duplicate" artifact's jar exists in the mock repo,
		// so a missing file cannot be the reason the entry is skipped
		const slf4jDir = path.join(tmpM2Repo, 'org', 'slf4j', 'slf4j-api', '1.7.36')
		fs.mkdirSync(slf4jDir, { recursive: true })
		fs.writeFileSync(path.join(slf4jDir, 'slf4j-api-1.7.36.jar'), jarContent)
		expect(fs.existsSync(path.join(slf4jDir, 'slf4j-api-1.7.36.jar'))).to.equal(true)

		const provider = new Java_maven()
		const depTree = [
			'com.example:root:jar:1.0.0',
			'\\- log4j:log4j:jar:1.2.17:compile',
			'   \\- (org.slf4j:slf4j-api:jar:1.7.36:compile - omitted for duplicate)'
		].join('\n')

		// When building the hash map
		const hashMap = await provider._buildMavenHashMap(depTree, { 'TRUSTIFY_DA_MVN_REPO': tmpM2Repo })

		// Then the parenthesized slf4j entry is absent (skipped by the guard) even
		// though its jar exists, while the non-parenthesized log4j entry is hashed
		expect(hashMap.has('pkg:maven/org.slf4j/slf4j-api@1.7.36')).to.equal(false)
		expect(hashMap.has('pkg:maven/log4j/log4j@1.2.17')).to.equal(true)
	})

	/**
	 * Verifies that an "omitted for conflict" line — which carries a classifier and
	 * a conflict override — is skipped by the guard before any file I/O, even when
	 * the referenced jar is present in the mock .m2 repository. The resolved
	 * version's hash comes from the real (non-parenthesized) winner node elsewhere
	 * in the tree, never from the omitted loser line itself.
	 */
	test('verify _buildMavenHashMap skips omitted-for-conflict lines via the guard', async () => {
		// Given the omitted classified artifact's jar exists in the mock repo,
		// so a missing file cannot be the reason the entry is skipped
		const overrideDir = path.join(tmpM2Repo, 'io', 'netty', 'netty-transport', '4.2.0')
		fs.mkdirSync(overrideDir, { recursive: true })
		fs.writeFileSync(path.join(overrideDir, 'netty-transport-4.2.0-linux-x86_64.jar'), jarContent)

		const provider = new Java_maven()
		// A verbose-tree line where the classified dep loses a conflict to 4.2.0
		const depTree = [
			'com.example:root:jar:1.0.0',
			'\\- log4j:log4j:jar:1.2.17:compile',
			'   \\- (io.netty:netty-transport:jar:linux-x86_64:4.1.0:compile - omitted for conflict with 4.2.0)'
		].join('\n')

		// When building the hash map
		const hashMap = await provider._buildMavenHashMap(depTree, { 'TRUSTIFY_DA_MVN_REPO': tmpM2Repo })

		// Then the parenthesized conflict line yields no entry (guard-skipped before
		// I/O) under either the override PURL or the classified PURL, while the
		// non-parenthesized log4j entry is still hashed
		expect(hashMap.has('pkg:maven/io.netty/netty-transport@4.2.0')).to.equal(false)
		expect(hashMap.has('pkg:maven/io.netty/netty-transport@4.2.0-linux-x86_64')).to.equal(false)
		expect(hashMap.has('pkg:maven/log4j/log4j@1.2.17')).to.equal(true)
	})

	/**
	 * Verifies that a classified dependency declared with a non-compile scope
	 * (system) is detected as classified — the hash-map key and parseDep PURL
	 * agree and the hash attaches. Guards against scope-list drift between the
	 * two code paths.
	 */
	test('verify classified dependency with system scope produces matching keys and attaches hash', async () => {
		// Given a classified jar for a system-scoped dependency
		const systemDir = path.join(tmpM2Repo, 'com', 'sun', 'tools', '1.8.0')
		fs.mkdirSync(systemDir, { recursive: true })
		fs.writeFileSync(path.join(systemDir, 'tools-1.8.0-jdk8.jar'), jarContent)

		const provider = new Java_maven()
		const depTree = 'com.example:root:jar:1.0.0\n\\- com.sun:tools:jar:jdk8:1.8.0:system'

		// When building the hash map
		const hashMap = await provider._buildMavenHashMap(depTree, { 'TRUSTIFY_DA_MVN_REPO': tmpM2Repo })

		// Then the classifier is folded into the version and both paths agree
		const purl = 'pkg:maven/com.sun/tools@1.8.0-jdk8'
		expect(provider.parseDep(depTree.split('\n')[1]).toString()).to.equal(purl)
		expect(hashMap.has(purl)).to.equal(true)
		expect(hashMap.get(purl)[0].content).to.equal(expectedDigest)
	})

	/**
	 * Drift guard: the hash-map key derivation must stay identical to the PURL
	 * parseDep() emits for the same line, across plain, classified, override, and
	 * scoped coordinate shapes. Both must route through the shared parseCoordinate
	 * / _coordinateToPurl helpers, so this equality holds by construction.
	 */
	test('verify parseDep and hash-map key derivation agree for all coordinate shapes', () => {
		const provider = new Java_maven()
		const lines = [
			'\\- log4j:log4j:jar:1.2.17:compile',
			'\\- io.netty:netty-transport:jar:linux-x86_64:4.1.0:compile',
			'\\- (io.netty:netty-transport:jar:linux-x86_64:4.1.0:compile - omitted for conflict with 4.2.0)',
			'\\- com.sun:tools:jar:jdk8:1.8.0:system',
			'\\- (org.foo:bar:jar:1.0.0:compile - omitted for conflict with 2.0.0)'
		]

		// For each shape, the key the hash map would store equals parseDep's PURL
		for (const line of lines) {
			const viaHashMap = provider._coordinateToPurl(provider.parseCoordinate(line)).toString()
			const viaParseDep = provider.parseDep(line).toString()
			expect(viaHashMap).to.equal(viaParseDep)
		}
	})
});
