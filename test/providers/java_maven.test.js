import fs from 'fs'
import { platform } from 'os';
import path from 'path';

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
		"pom_deps_with_no_ignore_common_paths"
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
}).beforeAll(() => clock = useFakeTimers(new Date('2023-08-07T00:00:00.000Z'))).afterAll(()=> {clock.restore()});

suite('testing the java-maven data provider with modules', () => {
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
}).beforeAll(() => clock = useFakeTimers(new Date('2023-08-07T00:00:00.000Z'))).afterAll(()=> {clock.restore()});

suite('testing the java-maven version parsing in getDependencies', () => {
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
}).beforeAll(() => clock = useFakeTimers(new Date('2023-08-07T00:00:00.000Z'))).afterAll(()=> {clock.restore()});
