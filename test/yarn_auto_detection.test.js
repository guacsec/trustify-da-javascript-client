import fs from 'node:fs';
import path from 'node:path';

import { expect } from 'chai';

import Javascript_yarn from '../src/providers/javascript_yarn.js';

suite('Yarn auto-detection', () => {
	let tempDir;
	let savedEnv;

	setup(() => {
		tempDir = fs.mkdtempSync('/tmp/yarn-test-');
		savedEnv = process.env.TRUSTIFY_DA_YARN_PATH;
		delete process.env.TRUSTIFY_DA_YARN_PATH;
	});

	teardown(() => {
		if (tempDir && fs.existsSync(tempDir)) {
			fs.rmSync(tempDir, { recursive: true, force: true });
		}
		if (savedEnv !== undefined) {
			process.env.TRUSTIFY_DA_YARN_PATH = savedEnv;
		} else {
			delete process.env.TRUSTIFY_DA_YARN_PATH;
		}
	});

	/**
	 * Creates a test fixture directory with package.json and yarn.lock.
	 * @param {Object} options - Configuration options
	 * @param {string} [options.packageManager] - packageManager field value
	 * @param {boolean} [options.yarnrc] - Whether to create .yarnrc.yml
	 * @returns {string} Path to package.json
	 */
	function createYarnFixture({ packageManager, yarnrc } = {}) {
		const manifest = {
			name: 'test-pkg',
			version: '1.0.0',
			dependencies: { 'lodash': '^4.17.21' }
		};
		if (packageManager) {
			manifest.packageManager = packageManager;
		}

		const manifestPath = path.join(tempDir, 'package.json');
		fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
		fs.writeFileSync(path.join(tempDir, 'yarn.lock'), '# Yarn lockfile v1\n');

		if (yarnrc) {
			fs.writeFileSync(path.join(tempDir, '.yarnrc.yml'), 'nodeLinker: node-modules\n');
		}

		return manifestPath;
	}

	test('auto-detects classic when TRUSTIFY_DA_YARN_PATH unset, no packageManager, no .yarnrc.yml', () => {
		createYarnFixture();
		// After _setUp runs with auto-detection, env var should be set
		// We can't easily test _setUp without mocking yarn binary, so we test the detection logic
		// by checking that the env var gets set
		const manifestPath = path.join(tempDir, 'package.json');

		// Import and instantiate to access the method
		const provider = new Javascript_yarn();
		const detected = provider._detectYarnPath(manifestPath);

		expect(detected).to.equal('/usr/local/bin/yarn-classic');
	});

	test('auto-detects berry when .yarnrc.yml present and no packageManager', () => {
		createYarnFixture({ yarnrc: true });
		const manifestPath = path.join(tempDir, 'package.json');

		const provider = new Javascript_yarn();
		const detected = provider._detectYarnPath(manifestPath);

		expect(detected).to.equal('/usr/local/bin/yarn-berry');
	});

	test('auto-detects classic from packageManager yarn@1.x', () => {
		createYarnFixture({ packageManager: 'yarn@1.22.22' });
		const manifestPath = path.join(tempDir, 'package.json');

		const provider = new Javascript_yarn();
		const detected = provider._detectYarnPath(manifestPath);

		expect(detected).to.equal('/usr/local/bin/yarn-classic');
	});

	test('auto-detects berry from packageManager yarn@4.x', () => {
		createYarnFixture({ packageManager: 'yarn@4.9.1' });
		const manifestPath = path.join(tempDir, 'package.json');

		const provider = new Javascript_yarn();
		const detected = provider._detectYarnPath(manifestPath);

		expect(detected).to.equal('/usr/local/bin/yarn-berry');
	});

	test('packageManager field takes precedence over .yarnrc.yml', () => {
		createYarnFixture({ packageManager: 'yarn@1.22.22', yarnrc: true });
		const manifestPath = path.join(tempDir, 'package.json');

		const provider = new Javascript_yarn();
		const detected = provider._detectYarnPath(manifestPath);

		expect(detected).to.equal('/usr/local/bin/yarn-classic');
	});

	test('returns null when manifest is not package.json', () => {
		const pomPath = path.join(tempDir, 'pom.xml');
		fs.writeFileSync(pomPath, '<project></project>');

		const provider = new Javascript_yarn();
		const detected = provider._detectYarnPath(pomPath);

		expect(detected).to.be.null;
	});

	test('returns null when yarn.lock does not exist', () => {
		const manifest = { name: 'test-pkg', version: '1.0.0' };
		const manifestPath = path.join(tempDir, 'package.json');
		fs.writeFileSync(manifestPath, JSON.stringify(manifest));
		// No yarn.lock created

		const provider = new Javascript_yarn();
		const detected = provider._detectYarnPath(manifestPath);

		expect(detected).to.be.null;
	});

	test('handles packageManager with hash suffix', () => {
		createYarnFixture({
			packageManager: 'yarn@4.9.1+sha512.abc123'
		});
		const manifestPath = path.join(tempDir, 'package.json');

		const provider = new Javascript_yarn();
		const detected = provider._detectYarnPath(manifestPath);

		expect(detected).to.equal('/usr/local/bin/yarn-berry');
	});

	test('handles malformed package.json gracefully', () => {
		const manifestPath = path.join(tempDir, 'package.json');
		fs.writeFileSync(manifestPath, '{ invalid json }');
		fs.writeFileSync(path.join(tempDir, 'yarn.lock'), '# Yarn lockfile v1\n');

		const provider = new Javascript_yarn();
		const detected = provider._detectYarnPath(manifestPath);

		// Falls back to .yarnrc.yml check (not present), so defaults to classic
		expect(detected).to.equal('/usr/local/bin/yarn-classic');
	});
});
