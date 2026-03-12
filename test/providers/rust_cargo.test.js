import fs from 'fs'
import path from 'path'

import { expect } from 'chai'
import esmock from 'esmock'
import { useFakeTimers } from 'sinon'

import { availableProviders, match } from '../../src/provider.js'
import rustCargo from '../../src/providers/rust_cargo.js'

let clock

/**
 * Creates a mocked rust_cargo provider that uses a pre-built cargo_metadata.json
 * instead of actually invoking the `cargo` binary.
 * @param {string} testDir - the test directory containing cargo_metadata.json and Cargo.toml
 * @returns {Promise<object>} the mocked provider module
 */
async function createMockProvider(testDir) {
	const metadataPath = path.join(testDir, 'cargo_metadata.json')
	const metadataJson = fs.readFileSync(metadataPath, 'utf-8')

	return esmock('../../src/providers/rust_cargo.js', {
		'../../src/tools.js': {
			getCustomPath: () => 'cargo',
			invokeCommand: (bin, args) => {
				if (args.includes('--version')) {
					return 'cargo 1.75.0 (1d8b05cdd 2023-11-20)'
				}
				if (args.includes('metadata')) {
					return metadataJson
				}
				return ''
			}
		}
	})
}

/**
 * Asserts that the provider output for a given analysis type matches the expected SBOM file.
 * @param {string} testDir - the test fixture directory
 * @param {'stack'|'component'} analysisType - 'stack' or 'component'
 */
async function assertSbomMatchesExpected(testDir, analysisType) {
	let expectedSbom = fs.readFileSync(`${testDir}/expected_sbom_${analysisType}_analysis.json`).toString()
	expectedSbom = JSON.stringify(JSON.parse(expectedSbom), null, 4)

	let provider = await createMockProvider(testDir)
	let manifest = `${testDir}/Cargo.toml`
	let providedData = analysisType === 'stack'
		? provider.provideStack(manifest)
		: provider.provideComponent(manifest)

	expect(providedData.ecosystem).equal('cargo')
	expect(providedData.contentType).equal('application/vnd.cyclonedx+json')
	expect(JSON.stringify(JSON.parse(providedData.content), null, 4).trim()).to.deep.equal(expectedSbom.trim())
}

/**
 * Creates a mock provider and returns the parsed SBOM for a given analysis type.
 * @param {string} testDir - the test fixture directory
 * @param {'stack'|'component'} analysisType - 'stack' or 'component'
 * @returns {Promise<object>} the parsed SBOM object
 */
async function getParsedSbom(testDir, analysisType) {
	let provider = await createMockProvider(testDir)
	let manifest = `${testDir}/Cargo.toml`
	let providedData = analysisType === 'stack'
		? provider.provideStack(manifest)
		: provider.provideComponent(manifest)
	return JSON.parse(providedData.content)
}

suite('testing the rust-cargo data provider', () => {
	[
		{ name: 'Cargo.toml', expected: true },
		{ name: 'package.json', expected: false },
		{ name: 'pom.xml', expected: false },
		{ name: 'go.mod', expected: false },
		{ name: 'cargo.toml', expected: false },
	].forEach(testCase => {
		test(`verify isSupported returns ${testCase.expected} for ${testCase.name}`, () =>
			expect(rustCargo.isSupported(testCase.name)).to.equal(testCase.expected)
		)
	});

	test('verify validateLockFile returns true when Cargo.lock exists', () => {
		expect(rustCargo.validateLockFile('test/providers/tst_manifests/cargo/cargo_single_crate_no_ignore')).to.equal(true)
	})

	test('verify validateLockFile returns true for member crate when Cargo.lock is at workspace root', () => {
		expect(rustCargo.validateLockFile('test/providers/tst_manifests/cargo/cargo_virtual_workspace/crate-a')).to.equal(true)
	})

	test('verify validateLockFile returns false when Cargo.lock does not exist anywhere', () => {
		expect(rustCargo.validateLockFile('test/providers/provider_manifests/cargo/without_lock_file')).to.equal(false)
	})

	test('verify match function finds Cargo provider with lock file', () => {
		let provider = match('test/providers/provider_manifests/cargo/with_lock_file/Cargo.toml', availableProviders)
		expect(provider).to.not.be.null
		expect(provider.isSupported('Cargo.toml')).to.be.true
	})

	test('verify match function throws when Cargo.lock is missing', () => {
		expect(() => match('test/providers/provider_manifests/cargo/without_lock_file/Cargo.toml', availableProviders))
			.to.throw('Cargo.toml requires a lock file')
	})

	test('verify workspace member crate finds Cargo.lock at workspace root', () => {
		let provider = match('test/providers/provider_manifests/cargo/workspace_member_with_lock/member1/Cargo.toml', availableProviders)
		expect(provider).to.not.be.null
		expect(provider.isSupported('Cargo.toml')).to.be.true
	})

	test('verify workspace member crate throws when workspace root has no Cargo.lock', () => {
		expect(() => match('test/providers/provider_manifests/cargo/workspace_member_without_lock/member1/Cargo.toml', availableProviders))
			.to.throw('Cargo.toml requires a lock file')
	})

	test('verify validateLockFile returns true for workspace member when Cargo.lock is at workspace root', () => {
		expect(rustCargo.validateLockFile('test/providers/provider_manifests/cargo/workspace_member_with_lock/member1')).to.equal(true)
	})

	test('verify validateLockFile returns false for workspace member when workspace root has no Cargo.lock', () => {
		expect(rustCargo.validateLockFile('test/providers/provider_manifests/cargo/workspace_member_without_lock/member1')).to.equal(false)
	})
}).beforeAll(() => clock = useFakeTimers(new Date('2023-08-07T00:00:00.000Z'))).afterAll(() => clock.restore());

suite('testing the rust-cargo single crate without ignore', () => {
	const testDir = 'test/providers/tst_manifests/cargo/cargo_single_crate_no_ignore'

	test('verify Cargo.toml sbom provided for stack analysis', async () => {
		await assertSbomMatchesExpected(testDir, 'stack')
	}).timeout(10000)

	test('verify Cargo.toml sbom provided for component analysis', async () => {
		await assertSbomMatchesExpected(testDir, 'component')
	}).timeout(10000)
}).beforeAll(() => clock = useFakeTimers(new Date('2023-08-07T00:00:00.000Z'))).afterAll(() => clock.restore());

suite('testing the rust-cargo single crate with ignore', () => {
	const testDir = 'test/providers/tst_manifests/cargo/cargo_single_crate_with_ignore'

	test('verify Cargo.toml sbom provided for stack analysis with ignored deps', async () => {
		await assertSbomMatchesExpected(testDir, 'stack')
	}).timeout(10000)

	test('verify Cargo.toml sbom provided for component analysis with ignored deps', async () => {
		await assertSbomMatchesExpected(testDir, 'component')
	}).timeout(10000)
}).beforeAll(() => clock = useFakeTimers(new Date('2023-08-07T00:00:00.000Z'))).afterAll(() => clock.restore());

suite('testing the rust-cargo virtual workspace', () => {
	const testDir = 'test/providers/tst_manifests/cargo/cargo_virtual_workspace'

	test('verify Cargo.toml sbom provided for stack analysis with virtual workspace', async () => {
		await assertSbomMatchesExpected(testDir, 'stack')
	}).timeout(10000)

	test('verify Cargo.toml sbom provided for component analysis with virtual workspace', async () => {
		await assertSbomMatchesExpected(testDir, 'component')
	}).timeout(10000)
}).beforeAll(() => clock = useFakeTimers(new Date('2023-08-07T00:00:00.000Z'))).afterAll(() => clock.restore());

suite('testing the rust-cargo workspace with root package', () => {
	const testDir = 'test/providers/tst_manifests/cargo/cargo_workspace_with_root'

	test('verify Cargo.toml sbom provided for stack analysis with workspace root package', async () => {
		await assertSbomMatchesExpected(testDir, 'stack')
	}).timeout(10000)

	test('verify Cargo.toml sbom provided for component analysis with workspace root package', async () => {
		await assertSbomMatchesExpected(testDir, 'component')
	}).timeout(10000)
}).beforeAll(() => clock = useFakeTimers(new Date('2023-08-07T00:00:00.000Z'))).afterAll(() => clock.restore());

suite('testing rust-cargo dependency filtering', () => {
	const testDir = 'test/providers/tst_manifests/cargo/cargo_single_crate_no_ignore'

	test('verify dev dependencies are excluded from stack analysis', async () => {
		let sbom = await getParsedSbom(testDir, 'stack')

		// tempfile is a dev dependency and should not appear in the SBOM
		expect(sbom.components.find(c => c.name === 'tempfile')).to.be.undefined

		// serde and tokio (normal deps) should be present
		expect(sbom.components.find(c => c.name === 'serde')).to.not.be.undefined
		expect(sbom.components.find(c => c.name === 'tokio')).to.not.be.undefined
	}).timeout(10000)

	test('verify dev dependencies are excluded from component analysis', async () => {
		let sbom = await getParsedSbom(testDir, 'component')

		expect(sbom.components.find(c => c.name === 'tempfile')).to.be.undefined
	}).timeout(10000)
}).beforeAll(() => clock = useFakeTimers(new Date('2023-08-07T00:00:00.000Z'))).afterAll(() => clock.restore());

suite('testing rust-cargo error handling', () => {
	test('verify error when cargo binary is not accessible', async () => {
		let provider = await esmock('../../src/providers/rust_cargo.js', {
			'../../src/tools.js': {
				getCustomPath: () => '/nonexistent/cargo',
				invokeCommand: () => {
					let err = new Error('spawn /nonexistent/cargo ENOENT')
					err.code = 'ENOENT'
					throw err
				}
			}
		})

		expect(() => provider.provideStack('test/providers/tst_manifests/cargo/cargo_single_crate_no_ignore/Cargo.toml'))
			.to.throw('cargo binary is not accessible at "/nonexistent/cargo"')
	}).timeout(10000)

	test('verify error when cargo metadata fails (e.g. invalid Cargo.toml)', async () => {
		let provider = await esmock('../../src/providers/rust_cargo.js', {
			'../../src/tools.js': {
				getCustomPath: () => 'cargo',
				invokeCommand: (bin, args) => {
					if (args.includes('--version')) {
						return 'cargo 1.75.0 (1d8b05cdd 2023-11-20)'
					}
					if (args.includes('metadata')) {
						throw new Error('error: failed to parse manifest at `/fake/Cargo.toml`\n\nCaused by:\n  missing field `name`')
					}
					return ''
				}
			}
		})

		expect(() => provider.provideStack('test/providers/tst_manifests/cargo/cargo_single_crate_no_ignore/Cargo.toml'))
			.to.throw('failed to execute cargo metadata')
	}).timeout(10000)
}).beforeAll(() => clock = useFakeTimers(new Date('2023-08-07T00:00:00.000Z'))).afterAll(() => clock.restore());

suite('testing rust-cargo ignore with underscore/hyphen normalization', () => {
	const testDir = 'test/providers/tst_manifests/cargo/cargo_single_crate_with_hyphen_ignore'

	test('verify hyphenated ignore name matches underscored crate in stack analysis', async () => {
		let sbom = await getParsedSbom(testDir, 'stack')

		// Cargo.toml uses "serde-derive" (hyphen) but metadata reports "serde_derive" (underscore)
		expect(sbom.components.find(c => c.name === 'serde_derive')).to.be.undefined

		// serde and tokio should still be present
		expect(sbom.components.find(c => c.name === 'serde')).to.not.be.undefined
		expect(sbom.components.find(c => c.name === 'tokio')).to.not.be.undefined
	}).timeout(10000)

	test('verify hyphenated ignore name matches underscored crate in component analysis', async () => {
		let sbom = await getParsedSbom(testDir, 'component')

		expect(sbom.components.find(c => c.name === 'serde_derive')).to.be.undefined
		expect(sbom.components.find(c => c.name === 'serde')).to.not.be.undefined
		expect(sbom.components.find(c => c.name === 'tokio')).to.not.be.undefined
	}).timeout(10000)
}).beforeAll(() => clock = useFakeTimers(new Date('2023-08-07T00:00:00.000Z'))).afterAll(() => clock.restore());

suite('testing rust-cargo ignore annotations with trustify-da-ignore', () => {
	const testDir = 'test/providers/tst_manifests/cargo/cargo_single_crate_with_ignore'

	test('verify trustify-da-ignore dependency is excluded from stack analysis', async () => {
		let sbom = await getParsedSbom(testDir, 'stack')

		// serde is annotated with trustify-da-ignore and should not appear
		expect(sbom.components.find(c => c.name === 'serde')).to.be.undefined
		expect(sbom.components.find(c => c.name === 'serde_derive')).to.be.undefined

		// tokio should still be present
		expect(sbom.components.find(c => c.name === 'tokio')).to.not.be.undefined
	}).timeout(10000)

	test('verify trustify-da-ignore dependency is excluded from component analysis', async () => {
		let sbom = await getParsedSbom(testDir, 'component')

		expect(sbom.components.find(c => c.name === 'serde')).to.be.undefined
	}).timeout(10000)
}).beforeAll(() => clock = useFakeTimers(new Date('2023-08-07T00:00:00.000Z'))).afterAll(() => clock.restore());

suite('testing rust-cargo ignore annotations with exhortignore', () => {
	const testDir = 'test/providers/tst_manifests/cargo/cargo_single_crate_with_exhortignore'

	test('verify exhortignore dependency is excluded from stack analysis', async () => {
		let sbom = await getParsedSbom(testDir, 'stack')

		// serde is annotated with exhortignore and should not appear
		expect(sbom.components.find(c => c.name === 'serde')).to.be.undefined
		expect(sbom.components.find(c => c.name === 'serde_derive')).to.be.undefined

		// tokio should still be present
		expect(sbom.components.find(c => c.name === 'tokio')).to.not.be.undefined
	}).timeout(10000)

	test('verify exhortignore dependency is excluded from component analysis', async () => {
		let sbom = await getParsedSbom(testDir, 'component')

		expect(sbom.components.find(c => c.name === 'serde')).to.be.undefined
	}).timeout(10000)
}).beforeAll(() => clock = useFakeTimers(new Date('2023-08-07T00:00:00.000Z'))).afterAll(() => clock.restore());

suite('testing rust-cargo virtual workspace ignore with trustify-da-ignore', () => {
	const testDir = 'test/providers/tst_manifests/cargo/cargo_virtual_workspace_with_ignore'

	test('verify sbom matches expected for stack analysis', async () => {
		await assertSbomMatchesExpected(testDir, 'stack')
	}).timeout(10000)

	test('verify sbom matches expected for component analysis', async () => {
		await assertSbomMatchesExpected(testDir, 'component')
	}).timeout(10000)

	test('verify serde is excluded and tokio is present in stack analysis', async () => {
		let sbom = await getParsedSbom(testDir, 'stack')

		expect(sbom.components.find(c => c.name === 'serde')).to.be.undefined
		expect(sbom.components.find(c => c.name === 'tokio')).to.not.be.undefined
		expect(sbom.components.find(c => c.name === 'crate-a')).to.not.be.undefined
		expect(sbom.components.find(c => c.name === 'crate-b')).to.not.be.undefined
	}).timeout(10000)

	test('verify component analysis has no member deps (no [workspace.dependencies])', async () => {
		let sbom = await getParsedSbom(testDir, 'component')

		// No [workspace.dependencies] → CA returns only the synthetic root
		expect(sbom.components.find(c => c.name === 'serde')).to.be.undefined
		expect(sbom.components.find(c => c.name === 'crate-a')).to.be.undefined
		expect(sbom.components.find(c => c.name === 'crate-b')).to.be.undefined
	}).timeout(10000)
}).beforeAll(() => clock = useFakeTimers(new Date('2023-08-07T00:00:00.000Z'))).afterAll(() => clock.restore());

suite('testing rust-cargo virtual workspace ignore with exhortignore', () => {
	const testDir = 'test/providers/tst_manifests/cargo/cargo_virtual_workspace_with_exhortignore'

	test('verify sbom matches expected for stack analysis', async () => {
		await assertSbomMatchesExpected(testDir, 'stack')
	}).timeout(10000)

	test('verify sbom matches expected for component analysis', async () => {
		await assertSbomMatchesExpected(testDir, 'component')
	}).timeout(10000)

	test('verify serde is excluded and tokio is present in stack analysis', async () => {
		let sbom = await getParsedSbom(testDir, 'stack')

		expect(sbom.components.find(c => c.name === 'serde')).to.be.undefined
		expect(sbom.components.find(c => c.name === 'tokio')).to.not.be.undefined
		expect(sbom.components.find(c => c.name === 'crate-a')).to.not.be.undefined
		expect(sbom.components.find(c => c.name === 'crate-b')).to.not.be.undefined
	}).timeout(10000)

	test('verify component analysis has no member deps (no [workspace.dependencies])', async () => {
		let sbom = await getParsedSbom(testDir, 'component')

		// No [workspace.dependencies] → CA returns only the synthetic root
		expect(sbom.components.find(c => c.name === 'serde')).to.be.undefined
		expect(sbom.components.find(c => c.name === 'crate-a')).to.be.undefined
		expect(sbom.components.find(c => c.name === 'crate-b')).to.be.undefined
	}).timeout(10000)
}).beforeAll(() => clock = useFakeTimers(new Date('2023-08-07T00:00:00.000Z'))).afterAll(() => clock.restore());

suite('testing rust-cargo workspace with root ignore with trustify-da-ignore', () => {
	const testDir = 'test/providers/tst_manifests/cargo/cargo_workspace_with_root_ignore'

	test('verify sbom matches expected for stack analysis', async () => {
		await assertSbomMatchesExpected(testDir, 'stack')
	}).timeout(10000)

	test('verify sbom matches expected for component analysis', async () => {
		await assertSbomMatchesExpected(testDir, 'component')
	}).timeout(10000)

	test('verify serde is excluded and sub-crate not in graph in stack analysis', async () => {
		let sbom = await getParsedSbom(testDir, 'stack')

		expect(sbom.components.find(c => c.name === 'serde')).to.be.undefined
		// sub-crate is a workspace member but NOT in the root's dependency graph
		expect(sbom.components.find(c => c.name === 'sub-crate')).to.be.undefined
		expect(sbom.components.find(c => c.name === 'tokio')).to.be.undefined
	}).timeout(10000)

	test('verify serde is excluded and sub-crate not in graph in component analysis', async () => {
		let sbom = await getParsedSbom(testDir, 'component')

		expect(sbom.components.find(c => c.name === 'serde')).to.be.undefined
		expect(sbom.components.find(c => c.name === 'sub-crate')).to.be.undefined
		expect(sbom.components.find(c => c.name === 'tokio')).to.be.undefined
	}).timeout(10000)
}).beforeAll(() => clock = useFakeTimers(new Date('2023-08-07T00:00:00.000Z'))).afterAll(() => clock.restore());

suite('testing rust-cargo virtual workspace with glob member patterns', () => {
	const testDir = 'test/providers/tst_manifests/cargo/cargo_virtual_workspace_glob_members'

	test('verify sbom matches expected for stack analysis', async () => {
		await assertSbomMatchesExpected(testDir, 'stack')
	}).timeout(10000)

	test('verify sbom matches expected for component analysis', async () => {
		await assertSbomMatchesExpected(testDir, 'component')
	}).timeout(10000)

	test('verify serde is excluded via glob-resolved member ignore', async () => {
		let sbom = await getParsedSbom(testDir, 'stack')

		expect(sbom.components.find(c => c.name === 'serde')).to.be.undefined
		expect(sbom.components.find(c => c.name === 'tokio')).to.not.be.undefined
		expect(sbom.components.find(c => c.name === 'crate-a')).to.not.be.undefined
		expect(sbom.components.find(c => c.name === 'crate-b')).to.not.be.undefined
	}).timeout(10000)

	test('verify component analysis has no member deps (no [workspace.dependencies])', async () => {
		let sbom = await getParsedSbom(testDir, 'component')

		// No [workspace.dependencies] → CA returns only the synthetic root
		expect(sbom.components.find(c => c.name === 'serde')).to.be.undefined
		expect(sbom.components.find(c => c.name === 'crate-a')).to.be.undefined
		expect(sbom.components.find(c => c.name === 'crate-b')).to.be.undefined
	}).timeout(10000)
}).beforeAll(() => clock = useFakeTimers(new Date('2023-08-07T00:00:00.000Z'))).afterAll(() => clock.restore());

suite('testing rust-cargo virtual workspace with [workspace.dependencies]', () => {
	const testDir = 'test/providers/tst_manifests/cargo/cargo_virtual_workspace_with_workspace_deps'

	test('verify sbom matches expected for stack analysis', async () => {
		await assertSbomMatchesExpected(testDir, 'stack')
	}).timeout(10000)

	test('verify sbom matches expected for component analysis', async () => {
		await assertSbomMatchesExpected(testDir, 'component')
	}).timeout(10000)

	test('verify CA includes only [workspace.dependencies] entries', async () => {
		let sbom = await getParsedSbom(testDir, 'component')

		// serde and tokio are in [workspace.dependencies] → should be present
		expect(sbom.components.find(c => c.name === 'serde')).to.not.be.undefined
		expect(sbom.components.find(c => c.name === 'tokio')).to.not.be.undefined

		// crate-a and crate-b are workspace members, not in [workspace.dependencies]
		expect(sbom.components.find(c => c.name === 'crate-a')).to.be.undefined
		expect(sbom.components.find(c => c.name === 'crate-b')).to.be.undefined

		// pin-project-lite is transitive, should not appear in CA
		expect(sbom.components.find(c => c.name === 'pin-project-lite')).to.be.undefined
	}).timeout(10000)

	test('verify SA includes full member trees', async () => {
		let sbom = await getParsedSbom(testDir, 'stack')

		expect(sbom.components.find(c => c.name === 'crate-a')).to.not.be.undefined
		expect(sbom.components.find(c => c.name === 'crate-b')).to.not.be.undefined
		expect(sbom.components.find(c => c.name === 'serde')).to.not.be.undefined
		expect(sbom.components.find(c => c.name === 'tokio')).to.not.be.undefined
		expect(sbom.components.find(c => c.name === 'pin-project-lite')).to.not.be.undefined
	}).timeout(10000)
}).beforeAll(() => clock = useFakeTimers(new Date('2023-08-07T00:00:00.000Z'))).afterAll(() => clock.restore());

suite('testing rust-cargo workspace with root ignore with exhortignore', () => {
	const testDir = 'test/providers/tst_manifests/cargo/cargo_workspace_with_root_exhortignore'

	test('verify sbom matches expected for stack analysis', async () => {
		await assertSbomMatchesExpected(testDir, 'stack')
	}).timeout(10000)

	test('verify sbom matches expected for component analysis', async () => {
		await assertSbomMatchesExpected(testDir, 'component')
	}).timeout(10000)

	test('verify serde is excluded and sub-crate not in graph in stack analysis', async () => {
		let sbom = await getParsedSbom(testDir, 'stack')

		expect(sbom.components.find(c => c.name === 'serde')).to.be.undefined
		// sub-crate is a workspace member but NOT in the root's dependency graph
		expect(sbom.components.find(c => c.name === 'sub-crate')).to.be.undefined
		expect(sbom.components.find(c => c.name === 'tokio')).to.be.undefined
	}).timeout(10000)

	test('verify serde is excluded and sub-crate not in graph in component analysis', async () => {
		let sbom = await getParsedSbom(testDir, 'component')

		expect(sbom.components.find(c => c.name === 'serde')).to.be.undefined
		expect(sbom.components.find(c => c.name === 'sub-crate')).to.be.undefined
		expect(sbom.components.find(c => c.name === 'tokio')).to.be.undefined
	}).timeout(10000)
}).beforeAll(() => clock = useFakeTimers(new Date('2023-08-07T00:00:00.000Z'))).afterAll(() => clock.restore());

suite('testing rust-cargo license detection', () => {
	const singleCrateLicenseDir = 'test/providers/tst_manifests/cargo/cargo_single_crate_with_license'
	const virtualWorkspaceLicenseDir = 'test/providers/tst_manifests/cargo/cargo_virtual_workspace_with_license'

	// readLicenseFromManifest unit tests are in license.test.js (shared across all providers)

	test('verify license is included in SBOM for single crate (stack analysis)', async () => {
		await assertSbomMatchesExpected(singleCrateLicenseDir, 'stack')
	}).timeout(10000)

	test('verify license is included in SBOM for single crate (component analysis)', async () => {
		await assertSbomMatchesExpected(singleCrateLicenseDir, 'component')
	}).timeout(10000)

	test('verify license is included in SBOM for virtual workspace (stack analysis)', async () => {
		await assertSbomMatchesExpected(virtualWorkspaceLicenseDir, 'stack')
	}).timeout(10000)

	test('verify license is included in SBOM for virtual workspace (component analysis)', async () => {
		await assertSbomMatchesExpected(virtualWorkspaceLicenseDir, 'component')
	}).timeout(10000)

	test('verify license field present in single crate SBOM metadata component', async () => {
		let sbom = await getParsedSbom(singleCrateLicenseDir, 'stack')
		expect(sbom.metadata.component.licenses).to.deep.equal([{ license: { id: 'ISC' } }])
	}).timeout(10000)

	test('verify license field present in virtual workspace SBOM metadata component', async () => {
		let sbom = await getParsedSbom(virtualWorkspaceLicenseDir, 'stack')
		expect(sbom.metadata.component.licenses).to.deep.equal([{ license: { id: 'ISC' } }])
	}).timeout(10000)

	test('verify no license field in SBOM when manifest has no license', async () => {
		let sbom = await getParsedSbom('test/providers/tst_manifests/cargo/cargo_single_crate_no_ignore', 'stack')
		expect(sbom.metadata.component.licenses).to.be.undefined
	}).timeout(10000)
}).beforeAll(() => clock = useFakeTimers(new Date('2023-08-07T00:00:00.000Z'))).afterAll(() => clock.restore());
