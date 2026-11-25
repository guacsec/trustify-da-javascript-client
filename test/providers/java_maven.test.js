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

suite('testing Maven scope selection', function () {
	this.timeout(40000)
	const fixtures = 'test/providers/tst_manifests/maven'
	const runtimeManifest = `${fixtures}/poms_deps_with_no_ignore_long/pom.xml`
	const scopedManifest = `${fixtures}/pom_with_multiple_modules/module3/pom.xml`

	for (const { scopes, included, excluded } of [
		{ scopes: 'compile,runtime', included: 'gson', excluded: 'javax.servlet-api' },
		{ scopes: 'test', included: 'assertj-core', excluded: 'gson' }
	]) {
		/** Verifies that the requested scope set determines which components appear. */
		test(`honors the ${scopes} scope selection`, async () => {
			// Given a POM with compile, provided, and test dependencies
			const provider = new Java_maven()
			const opts = { TRUSTIFY_DA_MVN_INCLUDE_SCOPES: scopes }

			// When generating a stack SBOM with the selected scopes
			const result = await provider.provideStack(scopedManifest, opts)

			// Then only the selected dependencies are represented
			const names = JSON.parse(result.content).components.map(component => component.name)
			expect(names).to.include(included)
			expect(names).not.to.include(excluded)
		})
	}

	/** Verifies that a runtime-only scan still honors an ignore marker on a compile declaration. */
	test('honors compile ignore markers in runtime-only analysis', async () => {
		// Given compile and runtime declarations of Kafka, plus an unrelated runtime dependency
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'maven-scope-test-'))
		try {
			const manifest = path.join(tmpDir, 'pom.xml')
			const pom = `<project>
				<modelVersion>4.0.0</modelVersion>
				<groupId>org.example</groupId><artifactId>scopes</artifactId><version>1.0</version>
				<dependencies>
					<dependency>
						<groupId>org.apache.kafka</groupId><artifactId>kafka-clients</artifactId>
						<version>3.0.1</version><scope>compile</scope>
					</dependency>
					<dependency>
						<groupId>org.apache.kafka</groupId><artifactId>kafka-clients</artifactId>
						<version>3.0.1</version><classifier>test</classifier><scope>runtime</scope>
					</dependency>
					<dependency>
						<groupId>com.google.code.gson</groupId><artifactId>gson</artifactId>
						<version>2.9.0</version><scope>runtime</scope>
					</dependency>
				</dependencies>
			</project>`
			const provider = new Java_maven()
			const opts = { TRUSTIFY_DA_MVN_INCLUDE_SCOPES: 'runtime' }

			// When scanning runtime scope, before and after marking the compile declaration
			fs.writeFileSync(manifest, pom)
			const unmarked = await provider.provideStack(manifest, opts)
			fs.writeFileSync(manifest, pom.replace('<scope>compile</scope>', '<scope>compile</scope><!-- trustify-da-ignore -->'))
			const marked = await provider.provideStack(manifest, opts)

			// Then the marker excludes Kafka by group/artifact without affecting Gson
			expect(JSON.parse(unmarked.content).components.map(component => component.purl))
				.to.include('pkg:maven/org.apache.kafka/kafka-clients@3.0.1-test')
			const names = JSON.parse(marked.content).components.map(component => component.name)
			expect(names).to.include('gson')
			expect(names).not.to.include('kafka-clients')
		} finally {
			fs.rmSync(tmpDir, { recursive: true, force: true })
		}
	})

	/** Verifies that a test-scope ignore marker is honored whether or not test scope is selected. */
	test('honors test ignore markers with and without test scope selected', async () => {
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'maven-scope-test-'))
		try {
			const manifest = path.join(tmpDir, 'pom.xml')
			const pom = fs.readFileSync(scopedManifest, 'utf8').replace('</dependencies>', `
				<dependency>
					<groupId>org.apache.kafka</groupId><artifactId>kafka-clients</artifactId>
					<version>3.0.1</version><scope>compile</scope>
				</dependency>
				<dependency>
					<groupId>org.apache.kafka</groupId><artifactId>kafka-clients</artifactId>
					<version>3.0.1</version><classifier>test</classifier><scope>test</scope>
				</dependency>
			</dependencies>`)
			const provider = new Java_maven()
			const analyze = async scopes => {
				const result = await provider.provideStack(manifest, { TRUSTIFY_DA_MVN_INCLUDE_SCOPES: scopes })
				return JSON.parse(result.content).components
			}

			fs.writeFileSync(manifest, pom)
			const unmarked = await analyze('compile,test')
			expect(unmarked.map(component => component.purl)).to.include('pkg:maven/org.apache.kafka/kafka-clients@3.0.1')
			expect(unmarked.map(component => component.name)).to.include('assertj-core')

			// Use a standalone test dependency for the selected-test case.
			fs.writeFileSync(manifest, pom
				.replace('<artifactId>assertj-core</artifactId>', '<artifactId>assertj-core</artifactId><!-- trustify-da-ignore -->')
				.replace('<classifier>test</classifier><scope>test</scope>',
					'<classifier>test</classifier><scope>test</scope><!-- trustify-da-ignore -->'))
			for (const [scopes, ignoredName] of [['compile', 'kafka-clients'], ['compile,test', 'assertj-core']]) {
				const names = (await analyze(scopes)).map(component => component.name)
				expect(names, scopes).to.include('gson')
				expect(names, scopes).not.to.include(ignoredName)
			}
		} finally {
			fs.rmSync(tmpDir, { recursive: true, force: true })
		}
	})

	/** Verifies that a classifier beginning with a scope name is not the scope column. */
	test('includes provided and system dependencies by default', () => {
		// Given a tree whose system dependency has a classifier beginning with "test"
		const provider = new Java_maven()
		const tree = [
			'org.example:module3:jar:1.0-SNAPSHOT',
			'+- example:provided-library:jar:1.0:provided',
			'\\- example:local-library:jar:test-fixture:1.0:system'
		].join(os.EOL)

		// When generating default and narrowed SBOMs from the same tree
		const defaults = provider.createSbomFileFromTextFormat(tree, [], {}, scopedManifest, new Map())
		const opts = { TRUSTIFY_DA_MVN_INCLUDE_SCOPES: 'compile,runtime' }
		const narrowed = provider.createSbomFileFromTextFormat(tree, [], opts, scopedManifest, new Map())

		// Then the default includes both dependencies, while the narrowed set excludes both
		expect(JSON.parse(defaults).components.map(component => component.name))
			.to.have.members(['provided-library', 'local-library'])
		expect(JSON.parse(narrowed).components ?? []).to.deep.equal([])
	})

	/** Verifies that omitted rows use the winning artifact's scope, including aliases and classifiers. */
	test('filters omitted rows by their resolved scope', () => {
		// Given compile artifacts repeated as omitted runtime rows
		const provider = new Java_maven()
		const tree = [
			'org.example:module3:jar:1.0-SNAPSHOT',
			'+- io.micrometer:micrometer-core:jar:1.8.5:compile',
			'+- org.apache.commons:commons-lang3:test-jar:tests:3.14.0:compile',
			'+- example:native:jar:linux:2.0:compile',
			'\\- io.micrometer:micrometer-registry-prometheus:jar:1.8.5:runtime',
			'   +- (io.micrometer:micrometer-core:jar:1.8.5:runtime - omitted for duplicate)',
			'   +- (org.apache.commons:commons-lang3:jar:tests:3.14.0:runtime - omitted for duplicate)',
			'   \\- (example:native:jar:linux:1.0:runtime - omitted for conflict with 2.0)'
		].join(os.EOL)
		const opts = { TRUSTIFY_DA_MVN_INCLUDE_SCOPES: 'runtime' }

		// When generating a runtime-only SBOM
		const sbom = JSON.parse(provider.createSbomFileFromTextFormat(tree, [], opts, scopedManifest, new Map()))

		// Then no runtime-labeled duplicate or conflict pulls a compile artifact into the SBOM
		expect(sbom.components.map(component => component.name))
			.to.have.members(['micrometer-registry-prometheus'])
	})

	/** Verifies that an excluded artifact type cannot overwrite the scope of a selected artifact. */
	test('keeps the compile JAR when the same coordinates have a test POM', () => {
		// Given a real Maven tree with two artifact types that use the same SBOM PURL
		const tree = [
			'org.example:module3:jar:1.0-SNAPSHOT',
			'+- com.google.code.gson:gson:jar:2.9.1:compile',
			'\\- com.google.code.gson:gson:pom:2.9.1:test'
		].join(os.EOL)

		// When generating a compile-only SBOM
		const opts = { TRUSTIFY_DA_MVN_INCLUDE_SCOPES: 'compile' }
		const sbom = JSON.parse(new Java_maven().createSbomFileFromTextFormat(tree, [], opts, scopedManifest, new Map()))

		// Then the compile JAR and its direct edge remain
		const gson = 'pkg:maven/com.google.code.gson/gson@2.9.1'
		expect(sbom.components?.map(component => component.purl)).to.deep.equal([gson])
		expect(sbom.dependencies[0].dependsOn).to.deep.equal([gson])
	})

	for (const { excluded, selected, opts } of [
		{ excluded: 'test', selected: 'compile', opts: {} },
		{ excluded: 'compile', selected: 'runtime', opts: { TRUSTIFY_DA_MVN_INCLUDE_SCOPES: 'runtime' } }
	]) {
		/** Verifies that selected dependencies cannot bypass an excluded parent or remain disconnected. */
		test(`prunes descendants reached only through an excluded ${excluded} parent`, () => {
			// Given two selected descendants behind an excluded parent and one direct dependency
			const provider = new Java_maven()
			const tree = [
				'org.example:module3:jar:1.0-SNAPSHOT',
				`+- example:excluded-parent:jar:1.0:${excluded}`,
				`|  \\- example:selected-child:jar:1.0:${selected}`,
				`|     \\- example:selected-grandchild:jar:1.0:${selected}`,
				`\\- example:selected-direct:jar:1.0:${selected}`
			].join(os.EOL)

			// When generating an SBOM without the parent's scope
			const sbom = JSON.parse(provider.createSbomFileFromTextFormat(tree, [], opts, scopedManifest, new Map()))

			// Then only the directly reachable dependency and its original edge remain
			expect(sbom.components.map(component => component.purl)).to.deep.equal(['pkg:maven/example/selected-direct@1.0'])
			expect(sbom.dependencies).to.deep.equal([
				{ ref: 'pkg:maven/org.example/module3@1.0-SNAPSHOT', dependsOn: ['pkg:maven/example/selected-direct@1.0'] },
				{ ref: 'pkg:maven/example/selected-direct@1.0', dependsOn: [] }
			])
		})
	}

	/** Verifies that an original path through a selected parent keeps a shared dependency reachable. */
	test('keeps a dependency under its selected parents when its resolved row is not', () => {
		// Given a compile dependency resolved under a test parent but also omitted under a compile parent
		const provider = new Java_maven()
		const tree = [
			'org.example:module3:jar:1.0-SNAPSHOT',
			'+- net.minidev:accessors-smart:jar:1.2:test',
			'|  \\- org.ow2.asm:asm:jar:5.0.4:compile',
			'|     \\- example:shared-child:jar:1.0:compile',
			'\\- io.quarkus:quarkus-core:jar:2.13.5.Final:compile',
			'   \\- (org.ow2.asm:asm:jar:5.0.4:compile - omitted for duplicate)'
		].join(os.EOL)

		// When generating an SBOM with the default selection
		const sbom = JSON.parse(provider.createSbomFileFromTextFormat(tree, [], {}, scopedManifest, new Map()))

		// Then the dependency stays under its compile parent and is not promoted to the root
		const dependsOn = Object.fromEntries(sbom.dependencies.map(dep => [dep.ref, dep.dependsOn]))
		expect(dependsOn['pkg:maven/org.example/module3@1.0-SNAPSHOT'])
			.to.deep.equal(['pkg:maven/io.quarkus/quarkus-core@2.13.5.Final'])
		expect(dependsOn['pkg:maven/io.quarkus/quarkus-core@2.13.5.Final'])
			.to.deep.equal(['pkg:maven/org.ow2.asm/asm@5.0.4'])
		expect(dependsOn['pkg:maven/org.ow2.asm/asm@5.0.4'])
			.to.deep.equal(['pkg:maven/example/shared-child@1.0'])
	})

	/** Verifies that a legacy conflict PURL does not make a distinct classified branch reachable. */
	test('prunes a disconnected branch behind a classified conflict', () => {
		// Given an omitted conflict under a selected parent and a classified winner under an excluded parent
		const tree = [
			'example:root:jar:1.0',
			'+- example:test-parent:jar:1.0:test',
			'|  \\- example:native:jar:linux:2.0:compile',
			'|     \\- example:child:jar:1.0:compile',
			'\\- example:compile-parent:jar:1.0:compile',
			'   \\- (example:native:jar:linux:1.0:compile - omitted for conflict with 2.0)'
		].join(os.EOL)

		// When generating a compile-only SBOM
		const opts = { TRUSTIFY_DA_MVN_INCLUDE_SCOPES: 'compile' }
		const sbom = JSON.parse(new Java_maven().createSbomFileFromTextFormat(tree, [], opts, scopedManifest, new Map()))

		// Then the conflict keeps its legacy PURL without retaining or reparenting the classified winner's child
		const parent = 'pkg:maven/example/compile-parent@1.0'
		const native = 'pkg:maven/example/native@2.0'
		expect(sbom.components.map(component => component.purl)).to.have.members([parent, native])
		expect(sbom.dependencies).to.have.deep.members([
			{ ref: 'pkg:maven/example/root@1.0', dependsOn: [parent] },
			{ ref: parent, dependsOn: [native] },
			{ ref: native, dependsOn: [] }
		])
	})

	/** Verifies that extra Maven arguments cannot override the default stack selection. */
	test('ignores a conflicting -Dscope in stack analysis', async () => {
		const provider = new Java_maven()
		const invoke = spy(provider, '_invokeCommand')
		const opts = { TRUSTIFY_DA_MVN_ARGS: '["-Dscope=test"]' }

		const result = await provider.provideStack(runtimeManifest, opts)
		const names = JSON.parse(result.content).components.map(component => component.name)

		// The defaults still include runtime dependencies and exclude tests.
		expect(names).to.include('micrometer-registry-prometheus')
		expect(names).not.to.include('spring-boot-starter-test')
		const scopeArgs = invoke.getCalls().flatMap(call => call.args[1])
			.filter(arg => arg.startsWith('-Dscope'))
		expect(scopeArgs).to.deep.equal([])
	})

	/** Verifies that version ranges resolve even outside compile scope. */
	test('resolves a runtime version range without forwarding -Dscope', () => {
		// Given the version-range fixture with its ranged dependency set to runtime scope
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'maven-scope-test-'))
		try {
			const pom = fs.readFileSync(`${fixtures}/pom_deps_with_version_range/pom.xml`, 'utf8')
			const manifest = path.join(tmpDir, 'pom.xml')
			fs.writeFileSync(manifest, pom.replace('<artifactId>log4j</artifactId>',
				'<artifactId>log4j</artifactId><scope>runtime</scope>'))
			const provider = new Java_maven()
			const invoke = spy(provider, '_invokeCommand')

			// When running component analysis with and without a conflicting scope argument
			const defaults = provider.provideComponent(manifest)
			invoke.resetHistory()
			const result = provider.provideComponent(manifest, {
				TRUSTIFY_DA_MVN_ARGS: '["-Dscope=test","-Dstyle.color=never"]'
			})

			// Then the range is resolved and only the unrelated property reaches Maven
			const purls = JSON.parse(result.content).components.map(component => component.purl)
			const defaultPurls = JSON.parse(defaults.content).components.map(component => component.purl)
			expect(purls).to.include('pkg:maven/log4j/log4j@1.2.17')
			expect(defaultPurls).to.deep.equal(purls)
			const commandArgs = invoke.getCalls().map(call => call.args[1])
				.filter(args => args[0] === '-q')
			expect(commandArgs.map(args => args[1])).to.deep.equal([
				'help:effective-pom', 'org.apache.maven.plugins:maven-dependency-plugin:3.6.0:tree'
			])
			for (const args of commandArgs) {
				expect(args).to.include('-Dstyle.color=never')
				expect(args.filter(arg => arg.startsWith('-Dscope'))).to.deep.equal([])
			}
		} finally {
			fs.rmSync(tmpDir, { recursive: true, force: true })
		}
	})

	/** Verifies that a test-scoped artifact cannot overwrite a runtime range's resolved version. */
	test('resolves a runtime range independently of a test-scoped classifier', () => {
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'maven-scope-test-'))
		try {
			const manifest = path.join(tmpDir, 'pom.xml')
			fs.writeFileSync(manifest, `<project>
				<modelVersion>4.0.0</modelVersion>
				<groupId>org.example</groupId><artifactId>ranges</artifactId><version>1.0</version>
				<dependencies>
					<dependency>
						<groupId>org.apache.kafka</groupId><artifactId>kafka-clients</artifactId>
						<version>[3.6.1]</version><scope>runtime</scope>
					</dependency>
					<dependency>
						<groupId>org.apache.kafka</groupId><artifactId>kafka-clients</artifactId>
						<version>3.0.1</version><classifier>test</classifier><scope>test</scope>
					</dependency>
				</dependencies>
			</project>`)

			const result = new Java_maven().provideComponent(manifest)
			const purls = JSON.parse(result.content).components.map(component => component.purl)
			expect(purls).to.deep.equal(['pkg:maven/org.apache.kafka/kafka-clients@3.6.1'])
		} finally {
			fs.rmSync(tmpDir, { recursive: true, force: true })
		}
	})

	/** Verifies that classified variants of one artifact resolve their ranges independently. */
	test('resolves ranges for classified variants of the same artifact separately', () => {
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'maven-scope-test-'))
		try {
			// Given two runtime Kafka variants, distinguished only by classifier, each with its own range
			const manifest = path.join(tmpDir, 'pom.xml')
			fs.writeFileSync(manifest, `<project>
				<modelVersion>4.0.0</modelVersion>
				<groupId>org.example</groupId><artifactId>ranges</artifactId><version>1.0</version>
				<dependencies>
					<dependency>
						<groupId>org.apache.kafka</groupId><artifactId>kafka-clients</artifactId>
						<version>[3.6.1]</version><scope>runtime</scope>
					</dependency>
					<dependency>
						<groupId>org.apache.kafka</groupId><artifactId>kafka-clients</artifactId>
						<version>[3.0.1]</version><classifier>test</classifier><scope>runtime</scope>
					</dependency>
				</dependencies>
			</project>`)

			// When running component analysis
			const result = new Java_maven().provideComponent(manifest)

			// Then each variant keeps the version Maven resolved for its own range
			const purls = JSON.parse(result.content).components.map(component => component.purl)
			expect(purls).to.have.members([
				'pkg:maven/org.apache.kafka/kafka-clients@3.6.1',
				'pkg:maven/org.apache.kafka/kafka-clients@3.0.1'
			])
		} finally {
			fs.rmSync(tmpDir, { recursive: true, force: true })
		}
	})

	/** Verifies that a type-implied Maven classifier does not prevent range resolution. */
	test('resolves a version range for a test JAR with an implicit classifier', () => {
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'maven-scope-test-'))
		try {
			// Given a non-test-scope dependency whose type implies the classifier "tests"
			const manifest = path.join(tmpDir, 'pom.xml')
			fs.writeFileSync(manifest, `<project>
				<modelVersion>4.0.0</modelVersion>
				<groupId>org.example</groupId><artifactId>ranges</artifactId><version>1.0</version>
				<dependencies><dependency>
					<groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId>
					<version>[3.14.0]</version><type>test-jar</type>
				</dependency></dependencies>
			</project>`)

			// When Maven resolves the range during component analysis
			const result = new Java_maven().provideComponent(manifest)

			// Then the report contains the concrete version, not the range
			expect(JSON.parse(result.content).components.map(component => component.purl))
				.to.deep.equal(['pkg:maven/org.apache.commons/commons-lang3@3.14.0'])
		} finally {
			fs.rmSync(tmpDir, { recursive: true, force: true })
		}
	})

	/** Verifies that an explicit empty classifier suppresses the type's implicit classifier. */
	test('resolves a test JAR range with an explicitly empty classifier', () => {
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'maven-scope-test-'))
		try {
			// Given an unclassified test-jar and a distinct jar with the tests classifier
			const manifest = path.join(tmpDir, 'pom.xml')
			fs.writeFileSync(manifest, `<project>
				<modelVersion>4.0.0</modelVersion>
				<groupId>org.example</groupId><artifactId>ranges</artifactId><version>1.0</version>
				<dependencies>
					<dependency>
						<groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId>
						<version>[3.13.0]</version><type>test-jar</type><classifier/>
					</dependency>
					<dependency>
						<groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId>
						<version>3.14.0</version><classifier>tests</classifier>
					</dependency>
				</dependencies>
			</project>`)

			// When Maven resolves the range during component analysis
			const result = new Java_maven().provideComponent(manifest)

			// Then the ranged artifact keeps its own resolved version
			expect(JSON.parse(result.content).components.map(component => component.purl)).to.have.members([
				'pkg:maven/org.apache.commons/commons-lang3@3.13.0',
				'pkg:maven/org.apache.commons/commons-lang3@3.14.0'
			])
		} finally {
			fs.rmSync(tmpDir, { recursive: true, force: true })
		}
	})

	/** Verifies that batch analysis sends the same selected dependency graph as single analysis. */
	test('applies the selected scopes to batch SBOMs', async () => {
		// Given the actual workspace discovery and providers, replacing only the backend call
		const client = await esmock('../../src/index.js', {
			'../../src/analysis.js': { default: { requestStackBatch: async sboms => sboms } }
		})
		const provider = new Java_maven()
		const opts = {
			TRUSTIFY_DA_BACKEND_URL: 'http://localhost:9999',
			TRUSTIFY_DA_MVN_INCLUDE_SCOPES: 'compile,runtime'
		}

		// When analyzing the same Maven project individually and in batch
		const single = JSON.parse((await provider.provideStack(scopedManifest, opts)).content)
		const batch = await client.stackAnalysisBatch(path.dirname(scopedManifest), false, opts)

		// Then batch sends only the dependencies selected by the single analysis
		const batchSbom = batch['pkg:maven/org.example/module3@1.0-SNAPSHOT']
		expect(batchSbom?.dependencies).to.deep.equal(single.dependencies)
		expect(batchSbom.components.map(component => component.name)).not.to.include('javax.servlet-api')
	})
})

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
