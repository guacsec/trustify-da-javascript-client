import fs from 'fs';
import os from 'os';
import path from 'path';

import { expect } from 'chai';

import golangGomodulesProvider from '../../src/providers/golang_gomodules.js';
import Java_gradle_groovy from '../../src/providers/java_gradle_groovy.js';
import pythonPipProvider from '../../src/providers/python_pip.js';

// Test LICENSE file fallback feature
suite('LICENSE file fallback for providers without manifest license support', () => {
	let tempDir;

	setup(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'license-test-'));
	});

	teardown(() => {
		if (tempDir && fs.existsSync(tempDir)) {
			fs.rmSync(tempDir, { recursive: true, force: true });
		}
	});

	test('Gradle provider should read LICENSE file when present', () => {
		const buildGradle = path.join(tempDir, 'build.gradle');
		const licenseFile = path.join(tempDir, 'LICENSE');

		fs.writeFileSync(buildGradle, 'plugins { id "java" }');
		fs.writeFileSync(licenseFile, 'Apache License, Version 2.0');

		const provider = new Java_gradle_groovy();
		const license = provider.readLicenseFromManifest(buildGradle);

		expect(license).to.equal('Apache-2.0');
	});

	test('Golang provider should read LICENSE file when present', () => {
		const goMod = path.join(tempDir, 'go.mod');
		const licenseFile = path.join(tempDir, 'LICENSE');

		fs.writeFileSync(goMod, 'module example.com/test');
		fs.writeFileSync(licenseFile, 'MIT License\n\nPermission is hereby granted');

		const license = golangGomodulesProvider.readLicenseFromManifest(goMod);

		expect(license).to.equal('MIT');
	});

	test('Python provider should read LICENSE file when present', () => {
		const requirements = path.join(tempDir, 'requirements.txt');
		const licenseFile = path.join(tempDir, 'LICENSE');

		fs.writeFileSync(requirements, 'requests==2.28.0');
		fs.writeFileSync(licenseFile, 'BSD 3-Clause License');

		const license = pythonPipProvider.readLicenseFromManifest(requirements);

		expect(license).to.equal('BSD-3-Clause');
	});

	test('Providers should return null when no LICENSE file exists', () => {
		const goMod = path.join(tempDir, 'go.mod');
		fs.writeFileSync(goMod, 'module example.com/test');

		const license = golangGomodulesProvider.readLicenseFromManifest(goMod);

		expect(license).to.be.null;
	});
});
