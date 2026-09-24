import fs from 'node:fs';
import path from 'node:path';

import { expect } from 'chai';
import esmock from 'esmock';

import Javascript_yarn from '../src/providers/javascript_yarn.js';

/**
 * Runs Javascript_yarn._setUp with the package-manager binary stubbed out, capturing
 * the opts threaded into super._setUp so we can assert the resolved Yarn path without
 * invoking a real yarn binary.
 * @param {string} manifestPath - Path to package.json
 * @param {{version?: string, opts?: Object}} [config]
 * @returns {Promise<{capturedOpts: Object}>}
 */
async function setUpWithStubbedYarn(manifestPath, { version = '1.22.22', opts = {} } = {}) {
	let capturedOpts;
	const key = 'TRUSTIFY_DA_YARN_PATH';
	const MockedYarn = await esmock('../src/providers/javascript_yarn.js', {
		'../src/providers/base_javascript.js': await esmock('../src/providers/base_javascript.js', {
			'../src/tools.js': {
				// Mirror getCustom precedence (opts wins, then env) so env-override tests are meaningful.
				getCustomPath: (name, o) => {
					capturedOpts = o;
					const fromOpts = typeof o?.[key] === 'string' && o[key] !== '' ? o[key] : undefined;
					return fromOpts ?? (process.env[key] || name);
				},
				invokeCommand: (_cmd, args) => (args.includes('--version') ? version : ''),
			},
		}),
	});
	new MockedYarn()._setUp(manifestPath, opts);
	return { capturedOpts };
}

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

	test('returns null for a non-Yarn packageManager even with yarn.lock present', () => {
		const manifestPath = createYarnFixture({ packageManager: 'npm@10.2.0' });

		const detected = new Javascript_yarn()._detectYarnPath(manifestPath);

		expect(detected).to.be.null;
	});

	test('_setUp threads the detected path into super._setUp without mutating process.env', async () => {
		const manifestPath = createYarnFixture({ packageManager: 'yarn@4.9.1' });

		const { capturedOpts } = await setUpWithStubbedYarn(manifestPath, { version: '4.9.1' });

		expect(capturedOpts.TRUSTIFY_DA_YARN_PATH).to.equal('/usr/local/bin/yarn-berry');
		expect(process.env.TRUSTIFY_DA_YARN_PATH).to.be.undefined;
	});

	test('_setUp still auto-detects when TRUSTIFY_DA_YARN_PATH is set but empty', async () => {
		process.env.TRUSTIFY_DA_YARN_PATH = '';
		const manifestPath = createYarnFixture();

		const { capturedOpts } = await setUpWithStubbedYarn(manifestPath, { version: '1.22.22' });

		expect(capturedOpts.TRUSTIFY_DA_YARN_PATH).to.equal('/usr/local/bin/yarn-classic');
	});

	test('_setUp respects an explicit TRUSTIFY_DA_YARN_PATH and skips auto-detection', async () => {
		process.env.TRUSTIFY_DA_YARN_PATH = '/custom/yarn';
		const manifestPath = createYarnFixture({ packageManager: 'yarn@4.9.1' });

		const { capturedOpts } = await setUpWithStubbedYarn(manifestPath, { version: '4.9.1' });

		// Auto-detection must not overwrite the caller-provided path.
		expect(capturedOpts.TRUSTIFY_DA_YARN_PATH).to.be.undefined;
	});
});
