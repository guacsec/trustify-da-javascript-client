import { fail } from 'assert';
import fs from 'fs'

import { expect } from 'chai'
import esmock from 'esmock';
import { useFakeTimers } from "sinon";

import { availableProviders, match } from '../../src/provider.js';
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
	default: { fail('Not implemented'); }
	}
}

suite('testing the javascript-npm data provider', async () => {
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
		{ name: 'yarn-berry/without_lock_file', validation: false }
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

		}).timeout(process.env.GITHUB_ACTIONS ? 30000 : 10000);
		test(`verify package.json data provided for ${providerName} - component analysis - ${scenario}`, async () => {
			// load the expected list for the scenario
			let expectedSbom = fs.readFileSync(`test/providers/tst_manifests/js-common/${testCase}/component_expected_sbom.json`,).toString().trim()
			let listing = fs.readFileSync(`test/providers/tst_manifests/${providerName}/${testCase}/listing_component.json`,).toString()

			// verify returned data matches expectation
			const provider = await createMockProvider(providerName, listing);
			const manifestPath = `test/providers/tst_manifests/${providerName}/${testCase}/package.json`;
			let providedDataForComponent = provider.provideComponent(manifestPath);

			compareSboms(providedDataForComponent.content, expectedSbom);
		}).timeout(process.env.GITHUB_ACTIONS ? 15000 : 10000)

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

}).beforeAll(() => clock = useFakeTimers(new Date('2023-08-07T00:00:00.000Z'))).afterAll(() => clock.restore());
