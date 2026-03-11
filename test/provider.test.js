import { expect } from 'chai'

import { match, matchForLicense, availableProviders } from "../src/provider.js"

suite('testing the provider utility function', () => {
	// create a dummy provider for 'dummy_file.typ'
	let dummyProvider = {
		isSupported: nameType => 'dummy_file.typ' === nameType,
		validateLockFile: () => {return true;},
		provideComponent: () => {}, // not required for this test
		provideStack: () => {} // not required for this test
	}

	test('when found matching provider should should return it', () => {
		let provider = match('/path/to/dummy_file.typ', [dummyProvider])
		expect(provider).to.be.equal(dummyProvider)
	});

	test('when no provider matched should throw error', () => {
		expect(() => match('/path/to/unknown.manifest', [dummyProvider]))
			.to.throw('unknown.manifest is not supported')
	})
});

suite('testing the matchForLicense utility function', () => {
	// create dummy providers with different manifest types
	const pomProvider = {
		isSupported: nameType => 'pom.xml' === nameType,
		validateLockFile: () => true,
		readLicenseFromManifest: () => 'Apache-2.0',
		provideComponent: () => {},
		provideStack: () => {}
	};

	const packageJsonProvider = {
		isSupported: nameType => 'package.json' === nameType,
		validateLockFile: () => false, // No lock file - should still match for license
		readLicenseFromManifest: () => 'MIT',
		provideComponent: () => {},
		provideStack: () => {}
	};

	const goModProvider = {
		isSupported: nameType => 'go.mod' === nameType,
		validateLockFile: () => true,
		readLicenseFromManifest: () => null,
		provideComponent: () => {},
		provideStack: () => {}
	};

	const testProviders = [pomProvider, packageJsonProvider, goModProvider];

	test('should match pom.xml provider by manifest name', () => {
		const provider = matchForLicense('/path/to/pom.xml', testProviders);
		expect(provider).to.equal(pomProvider);
	});

	test('should match package.json provider by manifest name', () => {
		const provider = matchForLicense('/path/to/package.json', testProviders);
		expect(provider).to.equal(packageJsonProvider);
	});

	test('should match go.mod provider by manifest name', () => {
		const provider = matchForLicense('/path/to/go.mod', testProviders);
		expect(provider).to.equal(goModProvider);
	});

	test('should match provider even when lock file does not exist', () => {
		// packageJsonProvider has validateLockFile returning false
		// but matchForLicense should not check lock file
		const provider = matchForLicense('/no/lock/here/package.json', testProviders);
		expect(provider).to.equal(packageJsonProvider);
	});

	test('should match provider with just filename (no full path)', () => {
		const provider = matchForLicense('pom.xml', testProviders);
		expect(provider).to.equal(pomProvider);
	});

	test('should throw error when no provider matches manifest type', () => {
		expect(() => matchForLicense('/path/to/unknown.txt', testProviders))
			.to.throw('unknown.txt is not supported');
	});

	test('should throw error for empty manifest name', () => {
		expect(() => matchForLicense('', testProviders))
			.to.throw('is not supported');
	});

	suite('real provider matching', () => {
		test('should match Java Maven provider for pom.xml', () => {
			const provider = matchForLicense('/some/path/pom.xml', availableProviders);
			expect(provider).to.exist;
			expect(provider.isSupported('pom.xml')).to.be.true;
		});

		test('should match Java Gradle Groovy provider for build.gradle', () => {
			const provider = matchForLicense('/some/path/build.gradle', availableProviders);
			expect(provider).to.exist;
			expect(provider.isSupported('build.gradle')).to.be.true;
		});

		test('should match Java Gradle Kotlin provider for build.gradle.kts', () => {
			const provider = matchForLicense('/some/path/build.gradle.kts', availableProviders);
			expect(provider).to.exist;
			expect(provider.isSupported('build.gradle.kts')).to.be.true;
		});

		test('should match JavaScript provider for package.json', () => {
			const provider = matchForLicense('/some/path/package.json', availableProviders);
			expect(provider).to.exist;
			expect(provider.isSupported('package.json')).to.be.true;
		});

		test('should match Golang provider for go.mod', () => {
			const provider = matchForLicense('/some/path/go.mod', availableProviders);
			expect(provider).to.exist;
			expect(provider.isSupported('go.mod')).to.be.true;
		});

		test('should match Python provider for requirements.txt', () => {
			const provider = matchForLicense('/some/path/requirements.txt', availableProviders);
			expect(provider).to.exist;
			expect(provider.isSupported('requirements.txt')).to.be.true;
		});

		test('all matched providers should have readLicenseFromManifest method', () => {
			const manifests = [
				'pom.xml',
				'build.gradle',
				'build.gradle.kts',
				'package.json',
				'go.mod',
				'requirements.txt'
			];

			manifests.forEach(manifest => {
				const provider = matchForLicense(`/test/${manifest}`, availableProviders);
				expect(provider.readLicenseFromManifest).to.be.a('function');
			});
		});
	});
});
