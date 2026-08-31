import { fail } from 'assert';
import fs from 'fs'

import { expect } from 'chai'
import esmock from 'esmock';
import { useFakeTimers } from "sinon";

import { availableProviders, match } from '../../src/provider.js';
import { sriToHash } from '../../src/providers/base_javascript.js';
import Manifest from '../../src/providers/manifest.js';
import { compareSboms } from '../utils/sbom_utils.js';

let clock

async function mockProvider(providerName, listingOutput, version) {

	const mockInvokeCommand = (_cmd, args) => {
		if (args.includes('--version')) {return version ? version : '0.0.0-mock';}
		return listingOutput;
	};

	return esmock(`../../src/providers/javascript_${providerName}.js`, {
		'../../src/providers/base_javascript.js': await esmock('../../src/providers/base_javascript.js', {
			'../../src/tools.js': {
				invokeCommand: mockInvokeCommand
			}
		})
	});
}

async function createMockProvider(providerName, listingOutput) {
	switch (providerName) {
	case 'npm': {
		const Javascript_npm = await mockProvider(providerName, listingOutput);
		return new Javascript_npm();
	}
	case 'pnpm': {
		const Javascript_pnpm = await mockProvider(providerName, listingOutput);
		return new Javascript_pnpm();
	}
	case 'yarn-classic': {
		const Javascript_yarn = await mockProvider('yarn', listingOutput, '1.22.22');
		return new Javascript_yarn();
	}
	case 'yarn-berry': {
		const Javascript_yarn = await mockProvider('yarn', listingOutput, '4.9.1');
		return new Javascript_yarn();
	}
	case 'bun': {
		const Javascript_bun = await mockProvider(providerName, listingOutput);
		return new Javascript_bun();
	}
	default: { fail('Not implemented'); }
	}
}

suite('testing the javascript-npm data provider', async () => {
	suiteSetup(() => clock = useFakeTimers(new Date('2023-08-07T00:00:00.000Z')));
	suiteTeardown(() => clock.restore());
	[
		{ name: 'npm/with_lock_file', validation: true },
		{ name: 'npm/without_lock_file', validation: false },
		{ name: 'npm/workspace_member_with_lock/packages/module-a', validation: true },
		{ name: 'npm/workspace_member_without_lock/packages/module-a', validation: false },
		{ name: 'pnpm/with_lock_file', validation: true },
		{ name: 'pnpm/without_lock_file', validation: false },
		{ name: 'yarn-classic/with_lock_file', validation: true },
		{ name: 'yarn-classic/without_lock_file', validation: false },
		{ name: 'yarn-berry/with_lock_file', validation: true },
		{ name: 'yarn-berry/without_lock_file', validation: false },
		{ name: 'bun/with_lock_file', validation: true },
		{ name: 'bun/without_lock_file', validation: false },
		{ name: 'bun/workspace_member_with_lock/packages/module-a', validation: true },
		{ name: 'bun/workspace_member_without_lock/packages/module-a', validation: false }
	].forEach(testCase => {
		test(`verify isSupported returns ${testCase.expected} for ${testCase.name}`, () => {
			let manifest = `test/providers/provider_manifests/${testCase.name}/package.json`;
			try {
				const provider = match(manifest, availableProviders);
				expect(provider).not.to.be.null;
				expect(testCase.validation).to.be.true;
			} catch (e) {
				expect(testCase.validation).to.be.false;
			}
		})
	});
	['npm', 'pnpm', 'yarn-classic', 'yarn-berry'].flatMap(providerName => [
		"package_json_deps_without_exhortignore_object",
		"package_json_deps_with_exhortignore_object",
		"package_json_deps_with_mixed_dep_types"
	].map(testCase => ({ providerName, testCase }))).forEach(({ providerName, testCase }) => {
		let scenario = testCase.replace('package_json_deps_', '').replaceAll('_', ' ')
		test(`verify package.json data provided for ${providerName} - stack analysis - ${scenario}`, async () => {
			// load the expected graph for the scenario
			let expectedSbom = fs.readFileSync(`test/providers/tst_manifests/${providerName}/${testCase}/stack_expected_sbom.json`,).toString();
			let listing = fs.readFileSync(`test/providers/tst_manifests/${providerName}/${testCase}/listing_stack.json`,).toString();

			const provider = await createMockProvider(providerName, listing);
			const manifestPath = `test/providers/tst_manifests/${providerName}/${testCase}/package.json`;
			let providedDataForStack = provider.provideStack(manifestPath);

			compareSboms(providedDataForStack.content, expectedSbom);

		}).timeout(30000);
		test(`verify package.json data provided for ${providerName} - component analysis - ${scenario}`, async () => {
			// load the expected list for the scenario
			let expectedSbom = fs.readFileSync(`test/providers/tst_manifests/js-common/${testCase}/component_expected_sbom.json`,).toString().trim()
			let listing = fs.readFileSync(`test/providers/tst_manifests/${providerName}/${testCase}/listing_component.json`,).toString()

			// verify returned data matches expectation
			const provider = await createMockProvider(providerName, listing);
			const manifestPath = `test/providers/tst_manifests/${providerName}/${testCase}/package.json`;
			let providedDataForComponent = provider.provideComponent(manifestPath);

			compareSboms(providedDataForComponent.content, expectedSbom);
		}).timeout(15000)

	});

	[
		{ providerName: 'pnpm', testCase: 'workspace_member' },
	].forEach(({ providerName, testCase }) => {
		test(`verify workspace member data for ${providerName} - stack analysis`, async () => {
			let expectedSbom = fs.readFileSync(`test/providers/tst_manifests/${providerName}/${testCase}/stack_expected_sbom.json`).toString();
			let listing = fs.readFileSync(`test/providers/tst_manifests/${providerName}/${testCase}/listing_stack.json`).toString();

			const provider = await createMockProvider(providerName, listing);
			const manifestPath = `test/providers/tst_manifests/${providerName}/${testCase}/packages/member-a/package.json`;
			let providedDataForStack = provider.provideStack(manifestPath);

			compareSboms(providedDataForStack.content, expectedSbom);
		}).timeout(30000);

		test(`verify workspace member data for ${providerName} - component analysis`, async () => {
			let expectedSbom = fs.readFileSync(`test/providers/tst_manifests/${providerName}/${testCase}/component_expected_sbom.json`).toString();
			let listing = fs.readFileSync(`test/providers/tst_manifests/${providerName}/${testCase}/listing_component.json`).toString();

			const provider = await createMockProvider(providerName, listing);
			const manifestPath = `test/providers/tst_manifests/${providerName}/${testCase}/packages/member-a/package.json`;
			let providedDataForComponent = provider.provideComponent(manifestPath);

			compareSboms(providedDataForComponent.content, expectedSbom);
		}).timeout(15000);
	});

	[
		{ providerName: 'yarn-berry', testCase: 'workspace_member' },
	].forEach(({ providerName, testCase }) => {
		test(`verify workspace member data for ${providerName} - stack analysis`, async () => {
			let expectedSbom = fs.readFileSync(`test/providers/tst_manifests/${providerName}/${testCase}/stack_expected_sbom.json`).toString();
			let listing = fs.readFileSync(`test/providers/tst_manifests/${providerName}/${testCase}/listing_stack.json`).toString();

			const provider = await createMockProvider(providerName, listing);
			const manifestPath = `test/providers/tst_manifests/${providerName}/${testCase}/packages/member-a/package.json`;
			let providedDataForStack = provider.provideStack(manifestPath);

			compareSboms(providedDataForStack.content, expectedSbom);
		}).timeout(30000);

		test(`verify workspace member data for ${providerName} - component analysis`, async () => {
			let expectedSbom = fs.readFileSync(`test/providers/tst_manifests/${providerName}/${testCase}/component_expected_sbom.json`).toString();
			let listing = fs.readFileSync(`test/providers/tst_manifests/${providerName}/${testCase}/listing_component.json`).toString();

			const provider = await createMockProvider(providerName, listing);
			const manifestPath = `test/providers/tst_manifests/${providerName}/${testCase}/packages/member-a/package.json`;
			let providedDataForComponent = provider.provideComponent(manifestPath);

			compareSboms(providedDataForComponent.content, expectedSbom);
		}).timeout(15000);
	});

	[
		{ providerName: 'npm', testCase: 'workspace_member' },
	].forEach(({ providerName, testCase }) => {
		/// Verifies that stack analysis resolves transitive dependencies for a workspace member.
		test(`verify workspace member data provided for ${providerName} - stack analysis`, async () => {
			// Given a workspace member manifest and mock listing from the workspace root
			const listing = fs.readFileSync(`test/providers/tst_manifests/${providerName}/${testCase}/listing_stack.json`).toString();
			const expectedSbom = fs.readFileSync(`test/providers/tst_manifests/${providerName}/${testCase}/stack_expected_sbom.json`).toString();
			const provider = await createMockProvider(providerName, listing);
			const manifestPath = `test/providers/tst_manifests/${providerName}/${testCase}/packages/member-a/package.json`;

			// When running stack analysis on the workspace member
			const result = provider.provideStack(manifestPath);

			// Then the SBOM should contain the member's transitive dependencies
			compareSboms(result.content, expectedSbom);
		}).timeout(30000);

		/// Verifies that component analysis resolves direct dependencies for a workspace member.
		test(`verify workspace member data provided for ${providerName} - component analysis`, async () => {
			// Given a workspace member manifest and mock listing from the workspace root
			const listing = fs.readFileSync(`test/providers/tst_manifests/${providerName}/${testCase}/listing_component.json`).toString();
			const expectedSbom = fs.readFileSync(`test/providers/tst_manifests/${providerName}/${testCase}/component_expected_sbom.json`).toString();
			const provider = await createMockProvider(providerName, listing);
			const manifestPath = `test/providers/tst_manifests/${providerName}/${testCase}/packages/member-a/package.json`;

			// When running component analysis on the workspace member
			const result = provider.provideComponent(manifestPath);

			// Then the SBOM should contain only the member's direct dependencies
			compareSboms(result.content, expectedSbom);
		}).timeout(15000);
	});

	['bun'].flatMap(providerName => [
		{ testCase: "package_json_deps_without_exhortignore_object", manifest: "package.json" },
		{ testCase: "package_json_deps_with_exhortignore_object", manifest: "package.json" },
		{ testCase: "package_json_deps_with_mixed_dep_types", manifest: "package.json" },
		{ testCase: "workspace_member", manifest: "packages/member-a/package.json" },
	].map(tc => ({ providerName, ...tc }))).forEach(({ providerName, testCase, manifest }) => {
		let scenario = testCase.replace('package_json_deps_', '').replaceAll('_', ' ')
		test(`verify package.json data provided for ${providerName} - stack analysis - ${scenario}`, async () => {
			let expectedSbom = fs.readFileSync(`test/providers/tst_manifests/${providerName}/${testCase}/stack_expected_sbom.json`).toString();

			const provider = await createMockProvider(providerName, '');
			const manifestPath = `test/providers/tst_manifests/${providerName}/${testCase}/${manifest}`;
			let providedDataForStack = provider.provideStack(manifestPath);

			compareSboms(providedDataForStack.content, expectedSbom);

		}).timeout(30000);
		test(`verify package.json data provided for ${providerName} - component analysis - ${scenario}`, async () => {
			let expectedSbom = fs.readFileSync(`test/providers/tst_manifests/${providerName}/${testCase}/component_expected_sbom.json`).toString().trim();

			const provider = await createMockProvider(providerName, '');
			const manifestPath = `test/providers/tst_manifests/${providerName}/${testCase}/${manifest}`;
			let providedDataForComponent = provider.provideComponent(manifestPath);

			compareSboms(providedDataForComponent.content, expectedSbom);
		}).timeout(15000)

	});

	test('loads a valid manifest with ignored dependencies', () => {
		const testCase = 'package_json_deps_with_exhortignore_object';
		const manifestPath = `test/providers/tst_manifests/npm/${testCase}/package.json`;
		const m = new Manifest(manifestPath);
		expect(m.name).to.be.equals('backend');
		expect(m.version).to.be.equals('1.0.0');
		expect(m.manifestPath).to.be.equals(manifestPath);
		expect(m.dependencies).to.have.all.members([
			"@hapi/joi",
			"backend",
			"bcryptjs",
			"dotenv",
			"express",
			"jsonwebtoken",
			"mongoose",
			"nodemon",
			"axios",
			"jsdom"]);
		const ignoredNames = m.ignored.map(dep => dep.name);
		expect(ignoredNames).to.have.all.members(['jsonwebtoken']);
	});

	test('loads a valid manifest without ignored dependencies', () => {
		const testCase = 'package_json_deps_without_exhortignore_object';
		const manifestPath = `test/providers/tst_manifests/npm/${testCase}/package.json`;
		const m = new Manifest(manifestPath);
		expect(m.name).to.be.equals('backend');
		expect(m.version).to.be.equals('1.0.0');
		expect(m.manifestPath).to.be.equals(manifestPath);
		expect(m.dependencies).to.have.all.members([
			"@hapi/joi",
			"backend",
			"bcryptjs",
			"dotenv",
			"express",
			"jsdom",
			"jsonwebtoken",
			"mongoose",
			"nodemon",
			"axios"]);
		expect(m.ignored).to.be.empty;
	});

	test('loads a manifest with mixed dependency types (peer, optional, bundled)', () => {
		const testCase = 'package_json_deps_with_mixed_dep_types';
		const manifestPath = `test/providers/tst_manifests/npm/${testCase}/package.json`;
		const m = new Manifest(manifestPath);
		expect(m.name).to.be.equals('mixed-deps-test');
		expect(m.version).to.be.equals('1.0.0');
		expect(m.dependencies).to.have.all.members([
			'express', 'axios', 'minimist', 'lodash']);
		expect(m.dependencies).to.not.include('jest');
		expect(m.dependencies).to.not.include('eslint');
		expect(m.peerDependencies).to.deep.equal({ minimist: '1.2.0' });
		expect(m.optionalDependencies).to.deep.equal({ lodash: '4.17.19' });
		expect(m.ignored).to.be.empty;
	});

	test('fails when the manifest does not exist', () => {
		const testCase = 'wrong_folder';
		const manifestPath = `test/providers/tst_manifests/npm/${testCase}/package.json`;
		expect(() => new Manifest(manifestPath)).to.throw(Error);
	});

	test('verify match with opts.TRUSTIFY_DA_WORKSPACE_DIR finds npm provider when lock is at workspace root', () => {
		const manifest = 'test/providers/provider_manifests/npm/with_lock_file/package.json'
		const opts = { TRUSTIFY_DA_WORKSPACE_DIR: 'test/providers/provider_manifests/npm/with_lock_file' }
		const provider = match(manifest, availableProviders, opts)
		expect(provider).to.not.be.null
		expect(provider.isSupported('package.json')).to.be.true
	})

	test('verify match with opts.TRUSTIFY_DA_WORKSPACE_DIR finds pnpm provider when lock is at workspace root', () => {
		const manifest = 'test/providers/provider_manifests/pnpm/with_lock_file/package.json'
		const opts = { TRUSTIFY_DA_WORKSPACE_DIR: 'test/providers/provider_manifests/pnpm/with_lock_file' }
		const provider = match(manifest, availableProviders, opts)
		expect(provider).to.not.be.null
		expect(provider.isSupported('package.json')).to.be.true
	})

	test('verify workspace member walks up and finds lock file at workspace root', () => {
		const manifest = 'test/providers/provider_manifests/npm/workspace_member_with_lock/packages/module-a/package.json'
		const provider = match(manifest, availableProviders)
		expect(provider).to.not.be.null
		expect(provider.isSupported('package.json')).to.be.true
	})

	test('verify workspace member throws when workspace root has no lock file', () => {
		const manifest = 'test/providers/provider_manifests/npm/workspace_member_without_lock/packages/module-a/package.json'
		expect(() => match(manifest, availableProviders))
			.to.throw('package.json requires a lock file')
	})

	test('verify match with opts.TRUSTIFY_DA_WORKSPACE_DIR overrides walk-up for workspace member', () => {
		const manifest = 'test/providers/provider_manifests/npm/workspace_member_with_lock/packages/module-a/package.json'
		const opts = { TRUSTIFY_DA_WORKSPACE_DIR: 'test/providers/provider_manifests/npm/workspace_member_with_lock' }
		const provider = match(manifest, availableProviders, opts)
		expect(provider).to.not.be.null
		expect(provider.isSupported('package.json')).to.be.true
	})

	test('verify pnpm workspace member stops at pnpm-workspace.yaml boundary', () => {
		const manifest = 'test/providers/provider_manifests/pnpm/workspace_member_without_lock/packages/module-a/package.json'
		expect(() => match(manifest, availableProviders))
			.to.throw('package.json requires a lock file')
	})

	test('verify match with wrong TRUSTIFY_DA_WORKSPACE_DIR fails even when walk-up would succeed', () => {
		const manifest = 'test/providers/provider_manifests/npm/workspace_member_with_lock/packages/module-a/package.json'
		const opts = { TRUSTIFY_DA_WORKSPACE_DIR: 'test/providers/provider_manifests/npm/workspace_member_without_lock' }
		expect(() => match(manifest, availableProviders, opts))
			.to.throw('package.json requires a lock file')
	})

	test('verify match with opts.TRUSTIFY_DA_WORKSPACE_DIR finds bun provider when lock is at workspace root', () => {
		const manifest = 'test/providers/provider_manifests/bun/with_lock_file/package.json'
		const opts = { TRUSTIFY_DA_WORKSPACE_DIR: 'test/providers/provider_manifests/bun/with_lock_file' }
		const provider = match(manifest, availableProviders, opts)
		expect(provider).to.not.be.null
		expect(provider.isSupported('package.json')).to.be.true
	})

	test('verify bun workspace member walks up and finds lock file at workspace root', () => {
		const manifest = 'test/providers/provider_manifests/bun/workspace_member_with_lock/packages/module-a/package.json'
		const provider = match(manifest, availableProviders)
		expect(provider).to.not.be.null
		expect(provider.isSupported('package.json')).to.be.true
	})

	test('verify bun workspace member throws when workspace root has no lock file', () => {
		const manifest = 'test/providers/provider_manifests/bun/workspace_member_without_lock/packages/module-a/package.json'
		expect(() => match(manifest, availableProviders))
			.to.throw('package.json requires a lock file')
	})

	test('verify match with wrong TRUSTIFY_DA_WORKSPACE_DIR fails for bun even when walk-up would succeed', () => {
		const manifest = 'test/providers/provider_manifests/bun/workspace_member_with_lock/packages/module-a/package.json'
		const opts = { TRUSTIFY_DA_WORKSPACE_DIR: 'test/providers/provider_manifests/bun/workspace_member_without_lock' }
		expect(() => match(manifest, availableProviders, opts))
			.to.throw('package.json requires a lock file')
	})

});

suite('sriToHash - SRI to CycloneDX hash conversion', () => {
	// The SHA-512 SRI for express@4.18.2 and its expected hex-encoded digest.
	const EXPRESS_SRI = 'sha512-5/PsL6iGPdfQ/lKM1UuielYgv3BUoJfz1aUwU9vHZ+J7gyvwdQXFEBIEIaxeGf0GIcreATNyBExtalisDbuMqQ==';
	const EXPRESS_HEX = 'e7f3ec2fa8863dd7d0fe528cd54ba27a5620bf7054a097f3d5a53053dbc767e27b832bf07505c510120421ac5e19fd0621cade013372044c6d6a58ac0dbb8ca9';
	// The well-known SHA-256 SRI of the empty input and its hex digest.
	const EMPTY_SHA256_SRI = 'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=';
	const EMPTY_SHA256_HEX = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

	test('converts a sha512 SRI string to a hex-encoded SHA-512 hash', () => {
		expect(sriToHash(EXPRESS_SRI)).to.deep.equal({ alg: 'SHA-512', content: EXPRESS_HEX });
	});

	test('converts a sha256 SRI string to a hex-encoded SHA-256 hash', () => {
		expect(sriToHash(EMPTY_SHA256_SRI)).to.deep.equal({ alg: 'SHA-256', content: EMPTY_SHA256_HEX });
	});

	test('uses only the first digest when several are space-separated', () => {
		expect(sriToHash(`${EXPRESS_SRI} ${EMPTY_SHA256_SRI}`)).to.deep.equal({ alg: 'SHA-512', content: EXPRESS_HEX });
	});

	test('ignores SRI options following the digest', () => {
		expect(sriToHash(`${EMPTY_SHA256_SRI}?foo=bar`)).to.deep.equal({ alg: 'SHA-256', content: EMPTY_SHA256_HEX });
	});

	[null, undefined, 42, '', '   ', 'notansri', 'md5-abc123', 'sha512-'].forEach(input => {
		test(`returns null for unparseable input: ${JSON.stringify(input)}`, () => {
			expect(sriToHash(input)).to.be.null;
		});
	});
});

suite('lock-file hash extraction (TC-5548)', () => {
	let hashClock;
	suiteSetup(() => hashClock = useFakeTimers(new Date('2023-08-07T00:00:00.000Z')));
	suiteTeardown(() => hashClock.restore());

	const WITHOUT_IGNORE = 'package_json_deps_without_exhortignore_object';
	const VALID_ALGS = ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'];

	// After aligning the drifted lock fixtures to the listing versions, every
	// direct dependency resolves to a hash for all four SRI/integrity-bearing
	// providers - proving hash extraction is wired end-to-end per provider.
	['npm', 'pnpm', 'yarn-classic', 'yarn-berry'].forEach(providerName => {
		test(`extracts a valid hash for every direct dependency - ${providerName} component analysis`, async () => {
			const listing = fs.readFileSync(`test/providers/tst_manifests/${providerName}/${WITHOUT_IGNORE}/listing_component.json`).toString();
			const provider = await createMockProvider(providerName, listing);
			const manifestPath = `test/providers/tst_manifests/${providerName}/${WITHOUT_IGNORE}/package.json`;
			const sbom = JSON.parse(provider.provideComponent(manifestPath).content);

			const libraries = sbom.components.filter(c => c.type === 'library');
			expect(libraries).to.not.be.empty;
			libraries.forEach(component => {
				expect(component.hashes, `${component.purl} should carry hashes`).to.be.an('array').that.is.not.empty;
				component.hashes.forEach(h => {
					expect(h.alg).to.be.oneOf(VALID_ALGS);
					expect(h.content).to.match(/^[0-9a-f]+$/);
				});
			});
		}).timeout(15000);
	});

	test('resolves the SHA-512 from package-lock.json integrity (SRI to hex) - npm', async () => {
		const listing = fs.readFileSync(`test/providers/tst_manifests/npm/${WITHOUT_IGNORE}/listing_component.json`).toString();
		const provider = await createMockProvider('npm', listing);
		const sbom = JSON.parse(provider.provideComponent(`test/providers/tst_manifests/npm/${WITHOUT_IGNORE}/package.json`).content);

		const express = sbom.components.find(c => c.purl === 'pkg:npm/express@4.18.2');
		expect(express.hashes).to.deep.equal([{
			alg: 'SHA-512',
			content: 'e7f3ec2fa8863dd7d0fe528cd54ba27a5620bf7054a097f3d5a53053dbc767e27b832bf07505c510120421ac5e19fd0621cade013372044c6d6a58ac0dbb8ca9'
		}]);
	}).timeout(15000);

	// Yarn Berry stores the Yarn cache checksum (not the npm SRI) in the
	// `checksum` field; the digest after the `<cacheKey>/` prefix is the SHA-512.
	test('resolves the Yarn Berry checksum field as a SHA-512 hash - yarn-berry', async () => {
		const testCase = 'package_json_deps_with_exhortignore_object';
		const listing = fs.readFileSync(`test/providers/tst_manifests/yarn-berry/${testCase}/listing_stack.json`).toString();
		const provider = await createMockProvider('yarn-berry', listing);
		const sbom = JSON.parse(provider.provideStack(`test/providers/tst_manifests/yarn-berry/${testCase}/package.json`).content);

		const express = sbom.components.find(c => c.purl === 'pkg:npm/express@4.21.2');
		expect(express.hashes).to.deep.equal([{
			alg: 'SHA-512',
			content: '38168fd0a32756600b56e6214afecf4fc79ec28eca7f7a91c2ab8d50df4f47562ca3f9dee412da7f5cea6b1a1544b33b40f9f8586dbacfbdada0fe90dbb10a1f'
		}]);
	}).timeout(30000);

	// When the lock file does not contain the resolved versions (fixture drift or
	// an unmatched tree), no hashes are emitted and analysis still succeeds.
	test('omits hashes when lock versions do not match the listing (graceful degradation) - npm', async () => {
		const testCase = 'package_json_deps_with_mixed_dep_types';
		const listing = fs.readFileSync(`test/providers/tst_manifests/npm/${testCase}/listing_component.json`).toString();
		const provider = await createMockProvider('npm', listing);
		const sbom = JSON.parse(provider.provideComponent(`test/providers/tst_manifests/npm/${testCase}/package.json`).content);

		const libraries = sbom.components.filter(c => c.type === 'library');
		expect(libraries).to.not.be.empty;
		libraries.forEach(component => expect(component.hashes, `${component.purl} should have no hashes`).to.be.undefined);
	}).timeout(15000);

	// Absent lock file: parsing degrades to an empty map (no error, no hashes).
	['npm', 'pnpm', 'yarn-classic', 'yarn-berry', 'bun'].forEach(providerName => {
		test(`returns an empty hash map when the lock file is absent (graceful degradation) - ${providerName}`, async () => {
			const provider = await createMockProvider(providerName, '');
			const map = provider._parseLockFileHashes('test/providers/tst_manifests');
			expect(map).to.be.a('Map');
			expect(map.size).to.equal(0);
		});
	});
});
