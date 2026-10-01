import { rejects } from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

import { expect } from 'chai';
import esmock from 'esmock';
import { spy } from 'sinon';

import Javascript_yarn from '../src/providers/javascript_yarn.js';
import { getCustomPath } from '../src/tools.js';

/**
 * Runs Javascript_yarn._setUp with the package-manager binary stubbed out, capturing
 * the opts threaded into super._setUp so we can assert the resolved Yarn path without
 * invoking a real yarn binary.
 * @param {string} manifestPath - Path to package.json
 * @param {{version?: string, opts?: Object, containerYarnAvailable?: boolean}} [config]
 * @returns {Promise<{capturedOpts: Object, invokedCommand: string, invokedOpts: Object, manifest: Object}>}
 */
async function setUpWithStubbedYarn(manifestPath, {
	version = '1.22.22', opts = {}, containerYarnAvailable = true
} = {}) {
	let capturedOpts;
	let invokedCommand;
	let invokedOpts;
	const MockedYarn = await esmock('../src/providers/javascript_yarn.js', {
		'node:fs': {
			existsSync: file => ['/usr/local/bin/yarn-classic', '/usr/local/bin/yarn-berry'].includes(file)
				? containerYarnAvailable : fs.existsSync(file),
		},
		'../src/providers/base_javascript.js': await esmock('../src/providers/base_javascript.js', {
			'../src/tools.js': {
				getCustomPath: (name, o) => {
					capturedOpts = o;
					return getCustomPath(name, o);
				},
				invokeCommand: (cmd, args, commandOpts) => {
					invokedCommand = cmd;
					invokedOpts = commandOpts;
					return args.includes('--version') ? version : '';
				},
			},
		}),
	});
	const provider = new MockedYarn();
	provider._setUp(manifestPath, opts);
	return { capturedOpts, invokedCommand, invokedOpts, manifest: provider._getManifest() };
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
	 * @param {boolean} [options.workspace] - Whether to return a workspace member manifest
	 * @returns {string} Path to package.json
	 */
	function createYarnFixture({ packageManager, yarnrc, workspace } = {}) {
		const manifest = {
			name: 'test-pkg',
			version: '1.0.0',
			dependencies: { 'lodash': '^4.17.21' }
		};
		if (packageManager) {
			manifest.packageManager = packageManager;
		}
		if (workspace) {
			manifest.workspaces = ['packages/*'];
		}

		const manifestPath = path.join(tempDir, 'package.json');
		fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
		fs.writeFileSync(path.join(tempDir, 'yarn.lock'), '# Yarn lockfile v1\n');

		if (yarnrc) {
			fs.writeFileSync(path.join(tempDir, '.yarnrc.yml'), 'nodeLinker: node-modules\n');
		}

		if (workspace) {
			const memberDir = path.join(tempDir, 'packages', 'member-a');
			fs.mkdirSync(memberDir, { recursive: true });
			const memberManifestPath = path.join(memberDir, 'package.json');
			fs.writeFileSync(memberManifestPath, JSON.stringify({ name: 'member-a', version: '1.0.0' }));
			return memberManifestPath;
		}

		return manifestPath;
	}

	['1.22.22', '3.1.1', '4.9.1'].forEach(version => {
		test(`_setUp preserves declared Yarn ${version} at the workspace root for a nested member`, async () => {
			const manifestPath = createYarnFixture({ packageManager: `yarn@${version}`, workspace: true });

			const { capturedOpts, invokedCommand, invokedOpts, manifest } = await setUpWithStubbedYarn(manifestPath, { version });

			expect(capturedOpts.TRUSTIFY_DA_YARN_PATH).to.equal('yarn');
			expect(invokedCommand).to.equal('yarn');
			expect(invokedOpts.cwd).to.equal(tempDir);
			expect(manifest.manifestPath).to.equal(manifestPath);
			expect(manifest.name).to.equal('member-a');
		});
	});

	test('detects Berry from .yarnrc.yml at the workspace root for a nested member', () => {
		const manifestPath = createYarnFixture({ yarnrc: true, workspace: true });

		expect(new Javascript_yarn()._detectYarnPath(manifestPath)).to.equal('/usr/local/bin/yarn-berry');
	});

	test('_setUp queries the declared Yarn version in TRUSTIFY_DA_WORKSPACE_DIR', async () => {
		const manifestPath = createYarnFixture({ packageManager: 'yarn@4.9.1', workspace: true });
		const workspaceDir = path.join(tempDir, 'selected-workspace');
		fs.mkdirSync(workspaceDir);
		fs.writeFileSync(path.join(workspaceDir, 'package.json'), JSON.stringify({ packageManager: 'yarn@1.22.22' }));
		fs.writeFileSync(path.join(workspaceDir, 'yarn.lock'), '# Yarn lockfile v1\n');

		const { capturedOpts, invokedOpts } = await setUpWithStubbedYarn(manifestPath, {
			opts: { TRUSTIFY_DA_WORKSPACE_DIR: workspaceDir },
		});

		expect(capturedOpts.TRUSTIFY_DA_YARN_PATH).to.equal('yarn');
		expect(invokedOpts.cwd).to.equal(workspaceDir);
	});

	test('auto-detects classic when TRUSTIFY_DA_YARN_PATH unset, no packageManager, no .yarnrc.yml', () => {
		createYarnFixture();
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

	['1.22.22', '3.1.1', '4.9.1'].forEach(version => {
		test(`uses yarn on PATH for declared packageManager yarn@${version}`, async () => {
			const manifestPath = createYarnFixture({ packageManager: `yarn@${version}` });

			expect(new Javascript_yarn()._detectYarnPath(manifestPath)).to.equal('yarn');
			const { capturedOpts, invokedCommand } = await setUpWithStubbedYarn(manifestPath, { version });
			expect(capturedOpts.TRUSTIFY_DA_YARN_PATH).to.equal('yarn');
			expect(invokedCommand).to.equal('yarn');
		});
	});

	test('packageManager field takes precedence over .yarnrc.yml', () => {
		createYarnFixture({ packageManager: 'yarn@1.22.22', yarnrc: true });
		const manifestPath = path.join(tempDir, 'package.json');

		const provider = new Javascript_yarn();
		const detected = provider._detectYarnPath(manifestPath);

		expect(detected).to.equal('yarn');
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

		expect(detected).to.equal('yarn');
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
		const manifestPath = createYarnFixture({ yarnrc: true });

		const { capturedOpts } = await setUpWithStubbedYarn(manifestPath, { version: '4.9.1' });

		expect(capturedOpts.TRUSTIFY_DA_YARN_PATH).to.equal('/usr/local/bin/yarn-berry');
		expect(process.env.TRUSTIFY_DA_YARN_PATH).to.be.undefined;
	});

	test('_setUp reads package.json once for detection and dependency analysis', async () => {
		const manifestPath = createYarnFixture({ packageManager: 'yarn@4.9.1' });
		const readFile = spy(fs, 'readFileSync');
		try {
			const { capturedOpts, manifest } = await setUpWithStubbedYarn(manifestPath, { version: '4.9.1' });

			expect(capturedOpts.TRUSTIFY_DA_YARN_PATH).to.equal('yarn');
			expect(manifest.dependencies).to.deep.equal(['lodash']);
			expect(readFile.getCalls().filter(call => call.args[0] === manifestPath)).to.have.lengthOf(1);
		} finally {
			readFile.restore();
		}
	});

	test('_setUp still auto-detects when TRUSTIFY_DA_YARN_PATH is set but empty', async () => {
		process.env.TRUSTIFY_DA_YARN_PATH = '';
		const manifestPath = createYarnFixture();

		const { capturedOpts } = await setUpWithStubbedYarn(manifestPath, { version: '1.22.22' });

		expect(capturedOpts.TRUSTIFY_DA_YARN_PATH).to.equal('/usr/local/bin/yarn-classic');
	});

	['1.22.22', '4.9.1'].forEach(version => {
		test(`_setUp falls back to yarn on PATH when the Yarn ${version} container binary is absent`, async () => {
			const manifestPath = createYarnFixture({ yarnrc: !version.startsWith('1.') });

			const { capturedOpts, invokedCommand } = await setUpWithStubbedYarn(manifestPath, {
				version, containerYarnAvailable: false,
			});

			expect(capturedOpts.TRUSTIFY_DA_YARN_PATH).to.equal('yarn');
			expect(invokedCommand).to.equal('yarn');
		});
	});

	test('_setUp preserves an explicit path in opts when container binaries are absent', async () => {
		const manifestPath = createYarnFixture({ packageManager: 'yarn@4.9.1' });
		const opts = { TRUSTIFY_DA_YARN_PATH: '/custom/yarn' };

		const { capturedOpts, invokedCommand } = await setUpWithStubbedYarn(manifestPath, {
			version: '4.9.1', opts, containerYarnAvailable: false,
		});

		expect(capturedOpts.TRUSTIFY_DA_YARN_PATH).to.equal('/custom/yarn');
		expect(invokedCommand).to.equal('/custom/yarn');
	});

	test('_setUp rejects an empty opts path even when the environment provides a path', async () => {
		process.env.TRUSTIFY_DA_YARN_PATH = '/custom/yarn';
		const manifestPath = createYarnFixture();

		await rejects(setUpWithStubbedYarn(manifestPath, {
			opts: { TRUSTIFY_DA_YARN_PATH: '' },
		}), { message: 'Executable path rejected: expected a non-empty string' });
	});

	test('_setUp respects an explicit TRUSTIFY_DA_YARN_PATH and skips auto-detection', async () => {
		process.env.TRUSTIFY_DA_YARN_PATH = '/custom/yarn';
		const manifestPath = createYarnFixture({ packageManager: 'yarn@4.9.1' });

		const { capturedOpts } = await setUpWithStubbedYarn(manifestPath, { version: '4.9.1' });

		// Auto-detection must not overwrite the caller-provided path.
		expect(capturedOpts.TRUSTIFY_DA_YARN_PATH).to.be.undefined;
	});
});
