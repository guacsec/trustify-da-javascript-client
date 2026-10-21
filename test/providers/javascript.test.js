import { fail } from 'assert';
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import { expect } from 'chai'
import esmock from 'esmock';
import { useFakeTimers } from "sinon";

import { getPackageVersion } from '../../src/package_version.js';
import { availableProviders, match } from '../../src/provider.js';
import { sriToHash } from '../../src/providers/base_javascript.js';
import Bun from '../../src/providers/javascript_bun.js';
import Manifest from '../../src/providers/manifest.js';
import { compareSboms } from '../utils/sbom_utils.js';

let clock

/** A valid SHA-512 SRI (is-number@7.0.0) reused across bun lockfile fixtures. */
const BUN_SRI = 'sha512-41Cifkg6e8TylSpdtTpeLVMqvSBEVzTttHvERD741+pnZ8ANv0004MRL43QKPDlK9cGvNp6NZWZUBlbGXYxxng==';
const BUN_SRI_HEX = Buffer.from(BUN_SRI.slice('sha512-'.length), 'base64').toString('hex');

/** Sorts components and dependency edges so two SBOMs compare order-independently. */
function canonical(sbom) {
	const data = typeof sbom === 'string' ? JSON.parse(sbom) : structuredClone(sbom);
	data.components.sort((a, b) => a.purl.localeCompare(b.purl));
	data.dependencies?.forEach(dep => dep.dependsOn.sort());
	data.dependencies?.sort((a, b) => a.ref.localeCompare(b.ref));
	return data;
}

/** Captures a directory's file contents so a run can be shown to leave it untouched. */
function snapshot(dir) {
	return fs.readdirSync(dir, { recursive: true }).sort().map(file => {
		const full = path.join(dir, file);
		return [file, fs.statSync(full).isDirectory() ? null : fs.readFileSync(full).toString('base64')];
	});
}

async function mockProvider(providerName, listingOutput, version) {
	if (providerName === 'npm' || providerName === 'yarn') {
		return (await import(`../../src/providers/javascript_${providerName}.js`)).default;
	}

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
		// Bun analysis is lockfile-only, so no subprocess mock is needed.
		return new Bun();
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
	['provideComponent', 'provideStack'].forEach(method => {
		test(`pnpm installs dependencies before ${method} when a lockfile already exists`, async () => {
			const fixtureDir = 'test/providers/tst_manifests/pnpm/package_json_deps_without_exhortignore_object';
			const listing = fs.readFileSync(`${fixtureDir}/listing_${method === 'provideStack' ? 'stack' : 'component'}.json`, 'utf-8');
			let installed = false;
			const Pnpm = await esmock('../../src/providers/javascript_pnpm.js', {
				'../../src/providers/base_javascript.js': await esmock('../../src/providers/base_javascript.js', {
					'../../src/tools.js': {
						invokeCommand: (_cmd, args) => {
							if (args.includes('--version')) { return '10.1.0'; }
							if (args[0] === 'install') {
								installed = true;
								return '';
							}
							return installed ? listing : '[{"name":"backend","version":"1.0.0"}]';
						}
					}
				})
			});

			const result = new Pnpm()[method](`${fixtureDir}/package.json`);

			expect(JSON.parse(result.content).components.map(component => component.name)).to.include('express');
		});
	});

	['pnpm'].flatMap(providerName => [
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

	/// Verifies that a manifest without a name field derives its name from the directory.
	test('derives name from directory when package.json has no name field', () => {
		// Given a temporary directory with a package.json that has no name field
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tc6923-'));
		fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({
			dependencies: { 'swagger-ui-dist': '^5.32.6' }
		}));

		try {
			// When loading the manifest
			const m = new Manifest(path.join(tmpDir, 'package.json'));

			// Then the name should be derived from the directory
			expect(m.name).to.equal(path.basename(tmpDir));
			expect(m.version).to.equal('v0.0.0');
		} finally {
			fs.rmSync(tmpDir, { recursive: true, force: true });
		}
	});

	/// Verifies that a declared name takes precedence over the directory fallback.
	test('uses declared name when present in package.json', () => {
		const manifestPath = 'test/providers/tst_manifests/npm/package_json_deps_without_exhortignore_object/package.json';
		const m = new Manifest(manifestPath);
		expect(m.name).to.equal('backend');
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

suite('bun lockfile-only analysis (TC-7014)', () => {
	let root;
	setup(() => { root = fs.mkdtempSync(path.join(os.tmpdir(), 'bun-lockfile-')); });
	teardown(() => { fs.rmSync(root, { recursive: true, force: true }); });

	/** Writes a package.json, a bun.lock and any extra manifests, returning the manifest path. */
	function project(manifest, lock, { manifestPath = 'package.json', extra = {} } = {}) {
		for (const [rel, content] of Object.entries(extra)) {
			const p = path.join(root, rel);
			fs.mkdirSync(path.dirname(p), { recursive: true });
			fs.writeFileSync(p, JSON.stringify(content));
		}
		fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify(manifest));
		fs.writeFileSync(path.join(root, 'bun.lock'), typeof lock === 'string' ? lock : JSON.stringify(lock));
		return path.join(root, manifestPath);
	}
	const stack = mp => JSON.parse(new Bun().provideStack(mp).content);
	const component = mp => JSON.parse(new Bun().provideComponent(mp).content);
	const edge = (sbom, from, to) => sbom.dependencies.find(dep => dep.ref === `pkg:npm/${from}`)?.dependsOn.includes(`pkg:npm/${to}`);

	for (const method of ['provideStack', 'provideComponent']) {
		/// Verifies bun analysis reads the graph without any subprocess or file writes (mirrors TC-6762).
		test(`bun ${method} makes no subprocess calls and changes no project files`, async () => {
			// Given a project with a bun.lock and a stale node_modules copy
			const lock = { lockfileVersion: 2, configVersion: 1,
				workspaces: { '': { name: 'app', dependencies: { alpha: '1.0.0' } } },
				packages: { alpha: ['alpha@1.0.0', '', { dependencies: { shared: '^1.0.0' } }, BUN_SRI], shared: ['shared@1.0.0', '', {}, BUN_SRI] } };
			const mp = project({ name: 'app', version: '1.0.0', dependencies: { alpha: '1.0.0' } }, lock);
			fs.mkdirSync(path.join(root, 'node_modules', 'alpha'), { recursive: true });
			fs.writeFileSync(path.join(root, 'node_modules', 'alpha', 'package.json'), '{"version":"99.0.0"}');
			const before = snapshot(root);

			// When analyzing with every subprocess path wired to throw
			const fail = () => { throw new Error('Unexpected subprocess invocation'); };
			const Provider = await esmock('../../src/providers/javascript_bun.js', {}, {
				'../../src/tools.js': { invokeCommand: fail },
				child_process: { execFileSync: fail, spawnSync: fail },
			});
			const provided = new Provider()[method](mp);

			// Then the SBOM comes from the lockfile and the project tree is untouched
			expect(JSON.parse(provided.content).components.some(c => c.purl === 'pkg:npm/alpha@1.0.0')).to.be.true;
			expect(provided.ecosystem).to.equal('npm');
			expect(snapshot(root)).to.deep.equal(before);
		});
	}

	/// Regression: aliases must report the npm-target identity, not the alias name.
	test('reports the npm-target identity and hash for aliases, not the alias name', () => {
		const mp = project({ name: 'app', version: '1.0.0', dependencies: { myalias: 'npm:is-number@7.0.0' } },
			{ lockfileVersion: 2, configVersion: 1, workspaces: { '': { name: 'app', dependencies: { myalias: 'npm:is-number@7.0.0' } } },
				packages: { myalias: ['is-number@7.0.0', '', {}, BUN_SRI] } });
		for (const read of [stack, component]) {
			const sbom = read(mp);
			expect(sbom.components.map(c => c.purl)).to.deep.equal(['pkg:npm/is-number@7.0.0']);
			expect(sbom.components[0].hashes).to.deep.equal([{ alg: 'SHA-512', content: BUN_SRI_HEX }]);
		}
	});

	/// Regression: a nested resolution must keep its own version instead of collapsing onto the root.
	test('resolves nested versions distinctly instead of collapsing onto the top-level entry', () => {
		// Given two parents that need conflicting versions of a shared dependency
		const mp = project({ name: 'app', version: '1.0.0', dependencies: { alpha: '1.0.0', beta: '1.0.0' } },
			{ lockfileVersion: 2, configVersion: 1, workspaces: { '': { name: 'app', dependencies: { alpha: '1.0.0', beta: '1.0.0' } } },
				packages: {
					alpha: ['alpha@1.0.0', '', { dependencies: { shared: '^1.0.0' } }, BUN_SRI],
					beta: ['beta@1.0.0', '', { dependencies: { shared: '^2.0.0' } }, BUN_SRI],
					shared: ['shared@1.0.0', '', {}, BUN_SRI],
					'beta/shared': ['shared@2.0.0', '', {}, BUN_SRI],
				} });

		// When building the SBOM
		const sbom = stack(mp);

		// Then each parent keeps its own resolved version of the shared dependency
		expect(edge(sbom, 'alpha@1.0.0', 'shared@1.0.0')).to.be.true;
		expect(edge(sbom, 'beta@1.0.0', 'shared@2.0.0')).to.be.true;
		expect(sbom.components.filter(c => c.name === 'shared').map(c => c.version).sort()).to.deep.equal(['1.0.0', '2.0.0']);
	});

	/// Regression: a workspace member reports its real version and dependencies, not a `workspace:` pseudo-version.
	test('reports a workspace member\'s real identity and dependencies', () => {
		const mp = project({ name: 'ws-root', private: true, workspaces: ['packages/member'] },
			{ lockfileVersion: 2, configVersion: 1,
				workspaces: { '': { name: 'ws-root' }, 'packages/member': { name: 'member', version: '2.0.0', dependencies: { alpha: '1.0.0' } } },
				packages: { alpha: ['alpha@1.0.0', '', {}, BUN_SRI], member: ['member@workspace:packages/member'] } },
			{ manifestPath: 'packages/member/package.json', extra: { 'packages/member/package.json': { name: 'member', version: '2.0.0', dependencies: { alpha: '1.0.0' } } } });
		const sbom = stack(mp);
		expect(sbom.metadata.component.purl).to.equal('pkg:npm/member@2.0.0');
		expect(edge(sbom, 'member@2.0.0', 'alpha@1.0.0')).to.be.true;
	});

	/// Preserves resolvable optional branches while skipping absent optional dependencies.
	test('preserves resolvable optional branches and skips absent ones', () => {
		const mp = project({ name: 'app', version: '1.0.0', dependencies: { host: '1.0.0' } },
			{ lockfileVersion: 2, configVersion: 1, workspaces: { '': { name: 'app', dependencies: { host: '1.0.0' } } },
				packages: {
					host: ['host@1.0.0', '', { optionalDependencies: { 'present-opt': '^1.0.0', 'absent-opt': '^1.0.0' } }, BUN_SRI],
					'present-opt': ['present-opt@1.0.0', '', {}, BUN_SRI],
				} });
		const sbom = stack(mp);
		expect(edge(sbom, 'host@1.0.0', 'present-opt@1.0.0')).to.be.true;
		expect(sbom.components.some(c => c.name === 'absent-opt')).to.be.false;
	});

	/// Regression: a missing required resolution is an error, not a silent omission.
	test('rejects a missing required resolution instead of silently dropping it', () => {
		const mp = project({ name: 'app', version: '1.0.0', dependencies: { alpha: '1.0.0' } },
			{ lockfileVersion: 2, configVersion: 1, workspaces: { '': { name: 'app', dependencies: { alpha: '1.0.0' } } },
				packages: { alpha: ['alpha@1.0.0', '', { dependencies: { missing: '^1.0.0' } }, BUN_SRI] } });
		expect(() => stack(mp)).to.throw(/out of date.*missing/);
	});

	/// Rejects a changed manifest declaration now that bun no longer re-syncs the lockfile.
	test('rejects a changed manifest declaration without writing files', () => {
		const lock = { lockfileVersion: 2, configVersion: 1, workspaces: { '': { name: 'app', dependencies: { alpha: '1.0.0' } } },
			packages: { alpha: ['alpha@1.0.0', '', {}, BUN_SRI] } };
		const mp = project({ name: 'app', version: '1.0.0', dependencies: { alpha: '1.0.0' } }, lock);
		fs.writeFileSync(mp, JSON.stringify({ name: 'app', version: '1.0.0', dependencies: { alpha: '^2.0.0' } }));
		const before = snapshot(root);
		expect(() => stack(mp)).to.throw(/out of date.*alpha/);
		expect(snapshot(root)).to.deep.equal(before);
	});

	for (const version of [0, 1, 2]) {
		/// Verifies every real lockfileVersion (0, 1, 2) is supported.
		test(`supports lockfileVersion ${version}`, () => {
			const mp = project({ name: 'app', version: '1.0.0', dependencies: { leaf: '1.0.0' } },
				{ lockfileVersion: version, configVersion: 1, workspaces: { '': { name: 'app', dependencies: { leaf: '1.0.0' } } },
					packages: { leaf: ['leaf@1.0.0', '', {}, BUN_SRI] } });
			expect(stack(mp).components.map(c => c.purl)).to.deep.equal(['pkg:npm/leaf@1.0.0']);
		});
	}

	/// Verifies an unsupported lockfileVersion fails closed with an actionable error.
	test('rejects an unsupported lockfile version', () => {
		const mp = project({ name: 'app', version: '1.0.0', dependencies: {} },
			{ lockfileVersion: 3, configVersion: 1, workspaces: { '': { name: 'app' } }, packages: {} });
		expect(() => stack(mp)).to.throw(/Unsupported bun lockfile version 3/);
	});

	/// Verifies hosted 3-tuple entries, empty-registry entries and SHA-1 integrity are all handled.
	test('handles hosted 3-tuple entries, empty-registry entries and SHA-1 integrity', () => {
		const sha1 = `sha1-${Buffer.from('ab'.repeat(20), 'hex').toString('base64')}`;
		const mp = project({ name: 'app', version: '1.0.0', dependencies: { hosted: 'github:o/r#abc', reg: '1.0.0' } },
			{ lockfileVersion: 2, configVersion: 1, workspaces: { '': { name: 'app', dependencies: { hosted: 'github:o/r#abc', reg: '1.0.0' } } },
				packages: {
					hosted: ['hosted@github:o/r#abc', {}, sha1],
					reg: ['reg@1.0.0', '', {}, BUN_SRI],
				} });
		const sbom = stack(mp);
		expect(sbom.components.some(c => c.name === 'hosted')).to.be.true;
		expect(sbom.components.find(c => c.name === 'hosted').hashes).to.deep.equal([{ alg: 'SHA-1', content: 'ab'.repeat(20) }]);
		expect(sbom.components.find(c => c.name === 'reg').hashes).to.deep.equal([{ alg: 'SHA-512', content: BUN_SRI_HEX }]);
	});

	/// Verifies a malformed bun.lock is rejected rather than silently yielding an empty graph.
	test('rejects a malformed bun.lock', () => {
		const mp = project({ name: 'app', version: '1.0.0', dependencies: {} }, '{ invalid');
		expect(() => stack(mp)).to.throw(/Cannot read/);
	});

	/// Verifies analysis requires a text lockfile when none is present.
	test('requires a bun.lock when none is present', () => {
		const mp = path.join(root, 'package.json');
		fs.writeFileSync(mp, JSON.stringify({ name: 'app', version: '1.0.0', dependencies: {} }));
		expect(() => stack(mp)).to.throw(/requires a lockfile/);
	});

	/// Verifies a binary bun.lockb (without a text bun.lock) yields an actionable migrate diagnostic.
	test('rejects a binary bun.lockb with a migrate-to-bun.lock diagnostic', () => {
		const mp = path.join(root, 'package.json');
		fs.writeFileSync(mp, JSON.stringify({ name: 'app', version: '1.0.0', dependencies: {} }));
		fs.writeFileSync(path.join(root, 'bun.lockb'), Buffer.from([0, 1, 2, 3]));
		expect(() => stack(mp)).to.throw(/bun\.lockb[\s\S]*bun\.lock/);
	});
});

suite('bun complete SBOM reference comparisons (TC-7014)', () => {
	let refClock;
	suiteSetup(() => { refClock = useFakeTimers(new Date('2023-08-07T00:00:00.000Z')); });
	suiteTeardown(() => { refClock.restore(); });
	const base = 'test/providers/tst_manifests/bun';
	const fixtures = ['alias', 'nested', 'optional', 'workspace', 'lockfile_v0', 'lockfile_v1', 'lockfile_v2'];
	for (const fixture of fixtures) {
		for (const { method, type } of [{ method: 'provideStack', type: 'stack' }, { method: 'provideComponent', type: 'component' }]) {
			test(`bun ${fixture} ${type} matches every SBOM field`, () => {
				const dir = `${base}/${fixture}`;
				const manifest = `${dir}/${fixture === 'workspace' ? 'packages/member/package.json' : 'package.json'}`;
				const actual = new Bun()[method](manifest);
				const expected = JSON.parse(fs.readFileSync(`${dir}/expected_${type}_sbom.json`, 'utf8'));
				expected.metadata.tools.components[0].version = getPackageVersion();
				expect(actual.contentType).to.equal('application/vnd.cyclonedx+json');
				expect(canonical(actual.content)).to.deep.equal(canonical(expected));
			});
		}
	}
});
