import crypto from 'node:crypto'
import fs from 'node:fs'
import os, { platform } from 'node:os'
import path from 'node:path'

import { expect } from 'chai'
import esmock from 'esmock';
import { useFakeTimers } from "sinon";
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
	suiteSetup(() => clock = useFakeTimers(new Date('2023-08-07T00:00:00.000Z')));
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
			let providedDataForStack =  javaMvnProvider.provideStack(`test/providers/tst_manifests/maven/${testCase}/pom.xml`)
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
	suiteSetup(() => clock = useFakeTimers(new Date('2023-08-07T00:00:00.000Z')));
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
	suiteSetup(() => clock = useFakeTimers(new Date('2023-08-07T00:00:00.000Z')));
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
	test('verify _buildMavenHashMap computes SHA-256 from jar files', () => {
		// Given a dependency tree with a dependency whose jar exists in the mock .m2 repo
		const provider = new Java_maven()
		const depTree = 'com.example:root:jar:1.0.0\n\\- log4j:log4j:jar:1.2.17:compile\n'

		// When building the hash map using the mock .m2 repo
		const hashMap = provider._buildMavenHashMap(depTree, { 'TRUSTIFY_DA_MVN_REPO': tmpM2Repo })

		// Then the hash map contains the correct SHA-256 digest for log4j
		const purl = 'pkg:maven/log4j/log4j@1.2.17'
		expect(hashMap.has(purl)).to.equal(true)
		expect(hashMap.get(purl)).to.deep.equal([{ alg: 'SHA-256', content: expectedDigest }])
	})

	/** Verifies that missing jar files result in omitted hashes rather than errors. */
	test('verify _buildMavenHashMap omits hash when jar file is not in cache', () => {
		// Given a dependency tree referencing an artifact not in the mock repo
		const provider = new Java_maven()
		const depTree = 'com.example:root:jar:1.0.0\n\\- org.missing:artifact:jar:1.0.0:compile\n'

		// When building the hash map
		const hashMap = provider._buildMavenHashMap(depTree, { 'TRUSTIFY_DA_MVN_REPO': tmpM2Repo })

		// Then the hash map is empty — no error thrown
		expect(hashMap.size).to.equal(0)
	})

	/** Verifies that custom Maven repository path via TRUSTIFY_DA_MVN_REPO is respected. */
	test('verify _buildMavenHashMap uses custom TRUSTIFY_DA_MVN_REPO path', () => {
		// Given the env var points to our mock .m2 repo
		const provider = new Java_maven()
		const depTree = 'com.example:root:jar:1.0.0\n\\- log4j:log4j:jar:1.2.17:compile\n'

		// When building hash map with TRUSTIFY_DA_MVN_REPO set via opts
		const hashMap = provider._buildMavenHashMap(depTree, { 'TRUSTIFY_DA_MVN_REPO': tmpM2Repo })

		// Then hash is found (proving the custom path was used)
		expect(hashMap.has('pkg:maven/log4j/log4j@1.2.17')).to.equal(true)
	})

	/** Verifies that packaging types like 'bundle' are mapped to .jar file extension. */
	test('verify _buildMavenHashMap maps bundle packaging to .jar extension', () => {
		// Given a mock jar under a groupId that uses 'bundle' packaging in the tree
		const bundleDir = path.join(tmpM2Repo, 'org', 'osgi', 'core', '6.0.0')
		fs.mkdirSync(bundleDir, { recursive: true })
		fs.writeFileSync(path.join(bundleDir, 'core-6.0.0.jar'), jarContent)

		const provider = new Java_maven()
		const depTree = 'com.example:root:jar:1.0.0\n\\- org.osgi:core:bundle:6.0.0:compile\n'

		// When building the hash map
		const hashMap = provider._buildMavenHashMap(depTree, { 'TRUSTIFY_DA_MVN_REPO': tmpM2Repo })

		// Then the bundle dependency gets a hash (mapped to .jar)
		expect(hashMap.has('pkg:maven/org.osgi/core@6.0.0')).to.equal(true)
		expect(hashMap.get('pkg:maven/org.osgi/core@6.0.0')[0].content).to.equal(expectedDigest)
	})

	/** Verifies that POM-only artifacts are skipped and no hash is computed. */
	test('verify _buildMavenHashMap skips pom packaging type', () => {
		const provider = new Java_maven()
		const depTree = 'com.example:root:jar:1.0.0\n\\- org.example:bom:pom:1.0.0:compile\n'

		// When building the hash map
		const hashMap = provider._buildMavenHashMap(depTree, { 'TRUSTIFY_DA_MVN_REPO': tmpM2Repo })

		// Then no hash entry for the pom-only artifact
		expect(hashMap.has('pkg:maven/org.example/bom@1.0.0')).to.equal(false)
	})

	/** Verifies that classified dependencies produce the correct file path with classifier in the filename. */
	test('verify _buildMavenHashMap handles classified dependencies', () => {
		// Given a jar with classifier in the expected path
		const classifiedDir = path.join(tmpM2Repo, 'io', 'netty', 'netty-transport', '4.1.0')
		fs.mkdirSync(classifiedDir, { recursive: true })
		fs.writeFileSync(path.join(classifiedDir, 'netty-transport-4.1.0-linux-x86_64.jar'), jarContent)

		const provider = new Java_maven()
		const depTree = 'com.example:root:jar:1.0.0\n\\- io.netty:netty-transport:jar:linux-x86_64:4.1.0:compile\n'

		// When building the hash map
		const hashMap = provider._buildMavenHashMap(depTree, { 'TRUSTIFY_DA_MVN_REPO': tmpM2Repo })

		// Then the classified dependency gets a hash keyed by the mangled PURL
		const purl = 'pkg:maven/io.netty/netty-transport@4.1.0-linux-x86_64'
		expect(hashMap.has(purl)).to.equal(true)
		expect(hashMap.get(purl)[0].content).to.equal(expectedDigest)
	})

	/** Verifies that hashes flow through createSbomFileFromTextFormat into SBOM components. */
	test('verify hashes appear in SBOM components via createSbomFileFromTextFormat', () => {
		// Given a dependency tree and a hash map with an entry
		const clock = useFakeTimers(new Date('2023-08-07T00:00:00.000Z'))
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

	/** Verifies that parenthesized (omitted/duplicate) lines in the dependency tree are skipped. */
	test('verify _buildMavenHashMap skips parenthesized duplicate entries', () => {
		const provider = new Java_maven()
		const depTree = [
			'com.example:root:jar:1.0.0',
			'\\- log4j:log4j:jar:1.2.17:compile',
			'   \\- (org.slf4j:slf4j-api:jar:1.7.36:compile - omitted for duplicate)'
		].join('\n')

		const hashMap = provider._buildMavenHashMap(depTree, { 'TRUSTIFY_DA_MVN_REPO': tmpM2Repo })

		// slf4j entry should not be in the hash map since it's a parenthesized duplicate
		expect(hashMap.has('pkg:maven/org.slf4j/slf4j-api@1.7.36')).to.equal(false)
	})
});
