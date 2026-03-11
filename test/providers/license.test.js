import path from 'path'

import { expect } from 'chai'

import golangGomodulesProvider from '../../src/providers/golang_gomodules.js'
import Java_gradle_groovy from '../../src/providers/java_gradle_groovy.js'
import Java_gradle_kotlin from '../../src/providers/java_gradle_kotlin.js'
import Java_maven from '../../src/providers/java_maven.js'
import Javascript_npm from '../../src/providers/javascript_npm.js'
import Javascript_pnpm from '../../src/providers/javascript_pnpm.js'
import Javascript_yarn from '../../src/providers/javascript_yarn.js'
import pythonPipProvider from '../../src/providers/python_pip.js'

suite('testing readLicenseFromManifest with existing test manifests', () => {

	suite('Java Maven provider', () => {
		const provider = new Java_maven();

		test('should read Apache-2.0 license when found', () => {
			const pomPath = path.resolve('test/providers/tst_manifests/maven/pom_deps_with_ignore_version_from_property/pom.xml');
			const license = provider.readLicenseFromManifest(pomPath);
			expect(license).to.equal('Apache-2.0');
		});

		test('should return null when license not present', () => {
			const pomPath = path.resolve('test/providers/tst_manifests/maven/pom_deps_with_no_ignore/pom.xml');
			const license = provider.readLicenseFromManifest(pomPath);
			expect(license).to.be.null;
		});
	});

	suite('Java Gradle Groovy provider', () => {
		const provider = new Java_gradle_groovy();

		test('should always return null (no standard license field)', () => {
			const gradlePath = path.resolve('test/providers/tst_manifests/gradle/deps_with_no_ignore_common_paths/build.gradle');
			const license = provider.readLicenseFromManifest(gradlePath);
			expect(license).to.be.null;
		});
	});

	suite('Java Gradle Kotlin provider', () => {
		const provider = new Java_gradle_kotlin();

		test('should always return null (no standard license field)', () => {
			const gradlePath = path.resolve('test/providers/tst_manifests/gradle/deps_with_no_ignore_common_paths/build.gradle.kts');
			const license = provider.readLicenseFromManifest(gradlePath);
			expect(license).to.be.null;
		});
	});

	suite('JavaScript npm provider', () => {
		const provider = new Javascript_npm();

		test('should read ISC license when found', () => {
			const packagePath = path.resolve('test/providers/tst_manifests/npm/package_json_deps_with_exhortignore_object/package.json');
			const license = provider.readLicenseFromManifest(packagePath);
			expect(license).to.equal('ISC');
		});

		test('should return null for non-existent file', () => {
			const license = provider.readLicenseFromManifest('/fake/path/package.json');
			expect(license).to.be.null;
		});
	});

	suite('JavaScript pnpm provider', () => {
		const provider = new Javascript_pnpm();

		test('should read ISC license when found', () => {
			const packagePath = path.resolve('test/providers/tst_manifests/pnpm/package_json_deps_with_exhortignore_object/package.json');
			const license = provider.readLicenseFromManifest(packagePath);
			expect(license).to.equal('ISC');
		});

		test('should return null for non-existent file', () => {
			const license = provider.readLicenseFromManifest('/fake/path/package.json');
			expect(license).to.be.null;
		});
	});

	suite('JavaScript yarn provider', () => {
		const provider = new Javascript_yarn();

		test('should read ISC license when found', () => {
			const packagePath = path.resolve('test/providers/tst_manifests/yarn-classic/package_json_deps_with_exhortignore_object/package.json');
			const license = provider.readLicenseFromManifest(packagePath);
			expect(license).to.equal('ISC');
		});

		test('should return null for non-existent file', () => {
			const license = provider.readLicenseFromManifest('/fake/path/package.json');
			expect(license).to.be.null;
		});
	});

	suite('Golang go.mod provider', () => {
		test('should always return null (no standard license field)', () => {
			const goModPath = path.resolve('test/providers/tst_manifests/golang/go_mod_no_ignore/go.mod');
			const license = golangGomodulesProvider.readLicenseFromManifest(goModPath);
			expect(license).to.be.null;
		});
	});

	suite('Python requirements.txt provider', () => {
		test('should always return null (no standard license field)', () => {
			const reqPath = path.resolve('test/providers/tst_manifests/pip/pip_requirements_txt_no_ignore/requirements.txt');
			const license = pythonPipProvider.readLicenseFromManifest(reqPath);
			expect(license).to.be.null;
		});
	});

	suite('All providers have readLicenseFromManifest method', () => {
		const allProviders = [
			{ name: 'Java Maven', instance: new Java_maven() },
			{ name: 'Java Gradle Groovy', instance: new Java_gradle_groovy() },
			{ name: 'Java Gradle Kotlin', instance: new Java_gradle_kotlin() },
			{ name: 'JavaScript npm', instance: new Javascript_npm() },
			{ name: 'JavaScript pnpm', instance: new Javascript_pnpm() },
			{ name: 'JavaScript yarn', instance: new Javascript_yarn() },
			{ name: 'Golang', instance: golangGomodulesProvider },
			{ name: 'Python', instance: pythonPipProvider }
		];

		allProviders.forEach(({ name, instance }) => {
			test(`${name} provider exports readLicenseFromManifest`, () => {
				expect(instance.readLicenseFromManifest).to.be.a('function');
			});

			test(`${name} provider readLicenseFromManifest accepts manifestPath parameter`, () => {
				// Should not throw when called with a path argument
				expect(() => instance.readLicenseFromManifest('/test/path')).to.not.throw();
			});
		});
	});
});
