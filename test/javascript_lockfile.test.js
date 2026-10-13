import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { expect } from 'chai';
import esmock from 'esmock';
import { useFakeTimers } from 'sinon';

import { getPackageVersion } from '../src/package_version.js';
import Npm from '../src/providers/javascript_npm.js';
import Yarn from '../src/providers/javascript_yarn.js';

const MANAGERS = ['npm', 'yarn-classic', 'yarn-berry'];
const SBOM_CASES = [
	{ method: 'provideStack', type: 'stack' },
	{ method: 'provideComponent', type: 'component' },
];

function canonical(sbom) {
	const data = typeof sbom === 'string' ? JSON.parse(sbom) : structuredClone(sbom);
	data.components.sort((a, b) => a.purl.localeCompare(b.purl));
	data.dependencies?.forEach(dep => dep.dependsOn.sort());
	data.dependencies?.sort((a, b) => a.ref.localeCompare(b.ref));
	return data;
}

function snapshot(dir) {
	return fs.readdirSync(dir, { recursive: true }).sort().map(file => {
		const full = path.join(dir, file);
		return [file, fs.statSync(full).isDirectory() ? null : fs.readFileSync(full).toString('base64')];
	});
}

suite('read-only JavaScript lockfile analysis', () => {
	let root;
	setup(() => { root = fs.mkdtempSync(path.join(os.tmpdir(), 'javascript-lockfile-')); });
	teardown(() => { fs.rmSync(root, { recursive: true, force: true }); });

	function fixture(manager, manifest = { name: 'app', version: '1.0.0', dependencies: { alpha: '^1.0.0' } },
		packages = { alpha: { version: '1.0.0', dependencies: { shared: '^1.0.0' } }, shared: { version: '1.0.0' } }) {
		const manifestPath = path.join(root, 'package.json');
		fs.writeFileSync(manifestPath, JSON.stringify(manifest));
		let lock;
		if (manager === 'npm') {
			lock = { lockfileVersion: 3, packages: { '': manifest } };
			for (const [name, entry] of Object.entries(packages)) { lock.packages[`node_modules/${name}`] = entry; }
		} else if (manager === 'yarn-classic') {
			lock = {};
			for (const [name, entry] of Object.entries(packages)) { lock[`${name}@^1.0.0`] = entry; }
		} else {
			lock = { __metadata: { version: 8 }, [`${manifest.name}@workspace:.`]: {
				version: '0.0.0-use.local', resolution: `${manifest.name}@workspace:.`,
				dependencies: Object.fromEntries(Object.entries({ ...manifest.devDependencies, ...manifest.dependencies, ...manifest.optionalDependencies }).map(([name, spec]) => [name, /^[a-z]+:/.test(spec) ? spec : `npm:${spec}`])),
				...(manifest.peerDependencies ? { peerDependencies: manifest.peerDependencies } : {}),
			} };
			for (const [name, entry] of Object.entries(packages)) {
				lock[`${name}@npm:^1.0.0`] = { ...entry, resolution: `${name}@npm:${entry.version}` };
			}
		}
		const lockPath = path.join(root, manager === 'npm' ? 'package-lock.json' : 'yarn.lock');
		fs.writeFileSync(lockPath, JSON.stringify(lock));
		return { manifestPath, lockPath, manifest, lock, provider: manager === 'npm' ? new Npm() : new Yarn() };
	}

	function result(test, method = 'provideStack') {
		return JSON.parse(test.provider[method](test.manifestPath).content);
	}

	function edge(sbom, from, to) {
		return sbom.dependencies.find(dep => dep.ref === `pkg:npm/${from}`)?.dependsOn.includes(`pkg:npm/${to}`);
	}

	for (const manager of MANAGERS) {
		for (const { method } of SBOM_CASES) {
			test(`${manager} ${method} makes no subprocess calls and changes no project files`, async () => {
				const test = fixture(manager);
				fs.mkdirSync(path.join(root, 'node_modules', 'alpha'), { recursive: true });
				fs.writeFileSync(path.join(root, 'node_modules', 'alpha', 'package.json'), '{"version":"99.0.0"}');
				fs.writeFileSync(path.join(root, '.yarnrc.yml'), 'nodeLinker: node-modules\n');
				fs.writeFileSync(path.join(root, '.npmrc'), 'ignore-scripts=true\n');
				const before = snapshot(root);
				const fail = () => { throw new Error('Unexpected subprocess invocation'); };
				const Provider = await esmock(`../src/providers/javascript_${manager === 'npm' ? 'npm' : 'yarn'}.js`, {}, {
					'../src/tools.js': { invokeCommand: fail },
					child_process: { execFileSync: fail, spawnSync: fail },
				});
				const savedPath = process.env.PATH;
				const savedPin = process.env.COREPACK_ENABLE_AUTO_PIN;
				process.env.PATH = '/no-package-managers';
				process.env.COREPACK_ENABLE_AUTO_PIN = '1';
				try {
					const provided = new Provider()[method](test.manifestPath, { TRUSTIFY_DA_YARN_PATH: '../invalid', TRUSTIFY_DA_NPM_PATH: '' });
					expect(JSON.parse(provided.content).components.some(c => c.purl === 'pkg:npm/alpha@1.0.0')).to.be.true;
					expect(provided.ecosystem).to.equal(manager === 'npm' ? 'npm' : manager);
					expect(snapshot(root)).to.deep.equal(before);
					expect(process.env.COREPACK_ENABLE_AUTO_PIN).to.equal('1');
				} finally {
					if (savedPath === undefined) { delete process.env.PATH; } else { process.env.PATH = savedPath; }
					if (savedPin === undefined) { delete process.env.COREPACK_ENABLE_AUTO_PIN; } else { process.env.COREPACK_ENABLE_AUTO_PIN = savedPin; }
				}
			});

			test(`${manager} ${method} rejects changed declarations without writing files`, () => {
				const test = fixture(manager);
				test.manifest.dependencies.alpha = '^2.0.0';
				fs.writeFileSync(test.manifestPath, JSON.stringify(test.manifest));
				const before = snapshot(root);
				expect(() => result(test, method)).to.throw(/Lockfile is out of date.*alpha/);
				expect(snapshot(root)).to.deep.equal(before);
			});
		}

		test(`${manager} emits direct versus transitive edges`, () => {
			const test = fixture(manager);
			const stack = result(test);
			const component = result(test, 'provideComponent');
			expect(edge(stack, 'app@1.0.0', 'alpha@1.0.0')).to.be.true;
			expect(edge(stack, 'alpha@1.0.0', 'shared@1.0.0')).to.be.true;
			expect(component.components.map(c => c.name)).to.deep.equal(['alpha']);
		});

		test(`${manager} preserves cycle edges without recursion overflow`, () => {
			const test = fixture(manager, undefined, {
				alpha: { version: '1.0.0', dependencies: { shared: '^1.0.0' } },
				shared: { version: '1.0.0', dependencies: { alpha: '^1.0.0' } },
			});
			const sbom = result(test);
			expect(edge(sbom, 'alpha@1.0.0', 'shared@1.0.0')).to.be.true;
			expect(edge(sbom, 'shared@1.0.0', 'alpha@1.0.0')).to.be.true;
			expect(sbom.components).to.have.lengthOf(2);
		});

		test(`${manager} preserves declared-only peer/optional entries and excludes development branches`, () => {
			const test = fixture(manager, { name: 'app', version: '1.0.0', dependencies: { alpha: '^1.0.0' },
				peerDependencies: { peer: '^1.0.0' }, optionalDependencies: { optional: '^1.0.0' }, devDependencies: { dev: '^1.0.0' } },
			{ alpha: { version: '1.0.0' }, dev: { version: '1.0.0' } });
			const sbom = result(test);
			expect(sbom.components.map(c => c.name).sort()).to.deep.equal(['alpha', 'optional', 'peer']);
			expect(edge(sbom, 'app@1.0.0', 'peer@%5E1.0.0')).to.be.true;
		});

		test(`${manager} refuses missing required edges`, () => {
			const test = fixture(manager, undefined, { alpha: { version: '1.0.0', dependencies: { missing: '^1.0.0' } } });
			expect(() => result(test)).to.throw(/out of date.*missing/);
		});

		test(`${manager} refuses malformed and absent lockfiles on direct provider calls`, () => {
			const test = fixture(manager);
			fs.writeFileSync(test.lockPath, '{ invalid');
			expect(() => result(test)).to.throw(/Cannot read/);
			fs.unlinkSync(test.lockPath);
			expect(() => result(test)).to.throw(/requires a lockfile/);
		});

		test(`${manager} rejects stale development declarations`, () => {
			const test = fixture(manager);
			test.manifest.devDependencies = { missingDev: '^1.0.0' };
			fs.writeFileSync(test.manifestPath, JSON.stringify(test.manifest));
			expect(() => result(test)).to.throw(/out of date.*missingDev/);
		});
	}

	for (const version of [2, 3]) {
		test(`npm supports lockfile version ${version}`, () => {
			const test = fixture('npm');
			test.lock.lockfileVersion = version;
			fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
			expect(result(test).components).to.have.lengthOf(2);
		});
	}

	for (const version of [1, 4]) {
		test(`npm rejects unsupported lockfile version ${version}`, () => {
			const test = fixture('npm');
			test.lock.lockfileVersion = version;
			fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
			expect(() => result(test)).to.throw(/Unsupported npm lockfile version/);
		});
	}

	test('npm honors shrinkwrap precedence, including projects without package-lock.json', () => {
		const test = fixture('npm');
		fs.copyFileSync(test.lockPath, path.join(root, 'npm-shrinkwrap.json'));
		test.lock.packages['node_modules/alpha'].version = '99.0.0';
		fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
		expect(result(test).components.some(c => c.version === '99.0.0')).to.be.false;
		fs.unlinkSync(test.lockPath);
		expect(test.provider.validateLockFile(root)).to.be.true;
		expect(result(test).components).to.have.lengthOf(2);
	});

	test('npm resolves nested versions from their recorded locations', () => {
		const test = fixture('npm', { name: 'app', version: '1.0.0', dependencies: { alpha: '^1.0.0', other: '^1.0.0' } }, {
			alpha: { version: '1.0.0', dependencies: { shared: '^1.0.0' } },
			other: { version: '1.0.0', dependencies: { shared: '^2.0.0' } }, shared: { version: '1.0.0' },
		});
		test.lock.packages['node_modules/other/node_modules/shared'] = { version: '2.0.0' };
		fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
		const sbom = result(test);
		expect(edge(sbom, 'alpha@1.0.0', 'shared@1.0.0')).to.be.true;
		expect(edge(sbom, 'other@1.0.0', 'shared@2.0.0')).to.be.true;
	});

	test('npm uses canonical alias identity without supplementing a duplicate alias', () => {
		const test = fixture('npm', { name: 'app', version: '1.0.0', optionalDependencies: { alias: 'npm:real@^1.0.0' } }, {
			alias: { name: 'real', version: '1.0.0', integrity: `sha512-${Buffer.from('ab'.repeat(64), 'hex').toString('base64')}` },
		});
		for (const { method } of SBOM_CASES) {
			expect(result(test, method).components.map(c => c.name)).to.deep.equal(['real']);
			expect(result(test, method).components[0].hashes).to.deep.equal([{ alg: 'SHA-512', content: 'ab'.repeat(64) }]);
		}
	});

	test('npm checks overrides without rejecting their intentional replacement versions', () => {
		const test = fixture('npm', { name: 'app', version: '1.0.0', dependencies: { alpha: '^1.0.0' }, overrides: { shared: '^2.0.0' } }, {
			alpha: { version: '1.0.0', dependencies: { shared: '^1.0.0' } }, shared: { version: '2.0.0' },
		});
		expect(edge(result(test), 'alpha@1.0.0', 'shared@2.0.0')).to.be.true;
	});

	test('npm limits version-qualified overrides to matching dependency requests', () => {
		const test = fixture('npm', { name: 'app', version: '1.0.0', dependencies: { alpha: '^1.0.0', other: '^1.0.0' }, overrides: { 'shared@^1.0.0': '^3.0.0' } }, {
			alpha: { version: '1.0.0', dependencies: { shared: '^1.0.0' } },
			other: { version: '1.0.0', dependencies: { shared: '^2.0.0' } }, shared: { version: '3.0.0' },
		});
		test.lock.packages['node_modules/other/node_modules/shared'] = { version: '2.0.0' };
		fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
		const sbom = result(test);
		expect(edge(sbom, 'alpha@1.0.0', 'shared@3.0.0')).to.be.true;
		expect(edge(sbom, 'other@1.0.0', 'shared@2.0.0')).to.be.true;
	});

	test('npm scopes nested overrides to the declaring ancestor', () => {
		const test = fixture('npm', { name: 'app', version: '1.0.0', dependencies: { alpha: '^1.0.0', other: '^1.0.0' }, overrides: { 'alpha@1.0.0': { shared: '^3.0.0' } } }, {
			alpha: { version: '1.0.0', dependencies: { shared: '^1.0.0' } },
			other: { version: '1.0.0', dependencies: { shared: '^1.0.0' } }, shared: { version: '1.0.0' },
		});
		test.lock.packages['node_modules/alpha/node_modules/shared'] = { version: '3.0.0' };
		fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
		const sbom = result(test);
		expect(edge(sbom, 'alpha@1.0.0', 'shared@3.0.0')).to.be.true;
		expect(edge(sbom, 'other@1.0.0', 'shared@1.0.0')).to.be.true;
	});

	for (const manager of MANAGERS) {
		test(`${manager} scopes workspace-member scans and validates the workspace root`, () => {
			const test = fixture(manager);
			const memberPath = path.join(root, 'packages', 'member', 'package.json');
			const otherPath = path.join(root, 'packages', 'other', 'package.json');
			fs.mkdirSync(path.dirname(memberPath), { recursive: true });
			fs.mkdirSync(path.dirname(otherPath), { recursive: true });
			const member = { name: 'member', version: '1.0.0', dependencies: { alpha: '^1.0.0' } };
			const other = { name: 'unrelated', version: '1.0.0', dependencies: { alpha: '^1.0.0' } };
			fs.writeFileSync(memberPath, JSON.stringify(member));
			fs.writeFileSync(otherPath, JSON.stringify(other));
			test.manifest.workspaces = ['packages/*'];
			fs.writeFileSync(test.manifestPath, JSON.stringify(test.manifest));
			if (manager === 'npm') {
				test.lock.packages['packages/member'] = member;
				test.lock.packages['packages/other'] = other;
				test.lock.packages['node_modules/member'] = { link: true, resolved: 'packages/member' };
				test.lock.packages['node_modules/unrelated'] = { link: true, resolved: 'packages/other' };
			} else if (manager === 'yarn-berry') {
				for (const [location, data] of [['packages/member', member], ['packages/other', other]]) {
					test.lock[`${data.name}@workspace:${location}`] = { version: '0.0.0-use.local', resolution: `${data.name}@workspace:${location}`, dependencies: { alpha: 'npm:^1.0.0' } };
				}
			}
			fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
			const sbom = JSON.parse(test.provider.provideStack(memberPath, { TRUSTIFY_DA_WORKSPACE_DIR: root }).content);
			expect(sbom.metadata.component.name).to.equal('member');
			expect(sbom.components.map(c => c.name).sort()).to.deep.equal(['alpha', 'shared']);
			expect(edge(sbom, 'member@1.0.0', 'alpha@1.0.0')).to.be.true;
			test.manifest.dependencies.alpha = '^2.0.0';
			fs.writeFileSync(test.manifestPath, JSON.stringify(test.manifest));
			expect(() => test.provider.provideStack(memberPath)).to.throw(/out of date.*alpha/);
		});
	}

	test('npm validates local link manifests and follows their locked dependencies', () => {
		const test = fixture('npm', { name: 'app', version: '1.0.0', dependencies: { local: 'file:local' } }, { shared: { version: '1.0.0' } });
		const local = { name: 'local', version: '1.0.0', dependencies: { shared: '^1.0.0' } };
		fs.mkdirSync(path.join(root, 'local'));
		fs.writeFileSync(path.join(root, 'local', 'package.json'), JSON.stringify(local));
		test.lock.packages.local = local;
		test.lock.packages['node_modules/local'] = { link: true, resolved: 'local' };
		fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
		expect(edge(result(test), 'local@1.0.0', 'shared@1.0.0')).to.be.true;
		local.dependencies.shared = '^2.0.0';
		fs.writeFileSync(path.join(root, 'local', 'package.json'), JSON.stringify(local));
		expect(() => result(test)).to.throw(/out of date.*shared/);
	});

	test('npm external local links cannot borrow the project root dependency locations', () => {
		const outside = `${root}-local`;
		const location = `../${path.basename(outside)}`;
		fs.mkdirSync(outside);
		try {
			const local = { name: 'local', version: '1.0.0', dependencies: { shared: '^1.0.0' } };
			fs.writeFileSync(path.join(outside, 'package.json'), JSON.stringify(local));
			const test = fixture('npm', { name: 'app', version: '1.0.0', dependencies: { local: `file:${location}` } }, { shared: { version: '1.0.0' } });
			test.lock.packages[location] = local;
			test.lock.packages['node_modules/local'] = { link: true, resolved: location };
			fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
			expect(() => result(test)).to.throw(/out of date.*shared.*no locked resolution/);
			test.lock.packages[`${location}/node_modules/shared`] = { version: '1.0.0' };
			fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
			expect(edge(result(test), 'local@1.0.0', 'shared@1.0.0')).to.be.true;
		} finally { fs.rmSync(outside, { recursive: true }); }
	});

	test('Berry resolves scoped registry aliases from combined descriptors', () => {
		const test = fixture('yarn-berry', { name: 'app', version: '1.0.0', dependencies: { alias: 'npm:@scope/real@^1.0.0' } }, {});
		test.lock['alias@npm:@scope/real@^1.0.0, @scope/real@npm:^1.0.0'] = { version: '1.0.0', resolution: '@scope/real@npm:1.0.0' };
		fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
		expect(result(test).components.map(c => c.purl)).to.deep.equal(['pkg:npm/%40scope/real@1.0.0']);
	});

	test('Yarn resolutions validate their intentional replacement version', () => {
		const test = fixture('yarn-classic', { name: 'app', version: '1.0.0', dependencies: { alpha: '^1.0.0' }, resolutions: { '**/shared': '^2.0.0' } }, {
			alpha: { version: '1.0.0', dependencies: { shared: '^1.0.0' } },
		});
		test.lock['shared@^2.0.0'] = { version: '2.0.0' };
		fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
		expect(edge(result(test), 'alpha@1.0.0', 'shared@2.0.0')).to.be.true;
	});

	test('Classic resolutions keep shared packages in distinct ancestry contexts', () => {
		const test = fixture('yarn-classic', { name: 'app', version: '1.0.0', dependencies: { alpha: '^1.0.0', other: '^1.0.0' }, resolutions: { 'alpha/plugin/shared': '^2.0.0' } }, {
			alpha: { version: '1.0.0', dependencies: { plugin: '^1.0.0' } }, other: { version: '1.0.0', dependencies: { plugin: '^1.0.0' } },
			plugin: { version: '1.0.0', dependencies: { shared: '^1.0.0' } }, shared: { version: '1.0.0' },
		});
		test.lock['shared@^2.0.0'] = { version: '2.0.0' };
		fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
		const sbom = result(test);
		expect(edge(sbom, 'plugin@1.0.0', 'shared@1.0.0')).to.be.true;
		expect(edge(sbom, 'plugin@1.0.0', 'shared@2.0.0')).to.be.true;
		test.lock['shared@^2.0.0'].dependencies = { plugin: '^1.0.0' };
		fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
		expect(() => result(test)).to.throw(/Unsupported.*cyclic graph with path-dependent/);
	});

	for (const selector of ['alpha/shared', 'alpha@npm:1.0.0/shared@npm:^1.0.0']) {
		test(`Berry scopes resolution ${selector} to the declaring locator`, () => {
			const test = fixture('yarn-berry', { name: 'app', version: '1.0.0', dependencies: { alpha: '^1.0.0', other: '^1.0.0' }, resolutions: { [selector]: '^2.0.0' } }, {
				alpha: { version: '1.0.0', dependencies: { shared: '^1.0.0' } },
				other: { version: '1.0.0', dependencies: { shared: '^1.0.0' } }, shared: { version: '1.0.0' },
			});
			test.lock['shared@npm:^2.0.0'] = { version: '2.0.0', resolution: 'shared@npm:2.0.0' };
			fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
			const sbom = result(test);
			expect(edge(sbom, 'alpha@1.0.0', 'shared@2.0.0')).to.be.true;
			expect(edge(sbom, 'other@1.0.0', 'shared@1.0.0')).to.be.true;
		});
	}

	test('Yarn chooses its format from the lockfile despite conflicting declarations', () => {
		const test = fixture('yarn-classic', { name: 'app', version: '1.0.0', packageManager: 'yarn@4.9.3', dependencies: { alpha: '^1.0.0' } });
		expect(test.provider.provideStack(test.manifestPath).ecosystem).to.equal('yarn-classic');
	});

	test('Berry reconstructs distinct peer contexts and unions their SBOM edges', () => {
		const test = fixture('yarn-berry', { name: 'app', version: '1.0.0', dependencies: { first: '^1.0.0', second: '^1.0.0' } }, {
			first: { version: '1.0.0', dependencies: { plugin: '^1.0.0', framework: '^1.0.0' } },
			second: { version: '1.0.0', dependencies: { plugin: '^1.0.0', framework: '^2.0.0' } },
			plugin: { version: '1.0.0', peerDependencies: { framework: '*' } }, framework: { version: '1.0.0' },
		});
		test.lock['framework@npm:^2.0.0'] = { version: '2.0.0', resolution: 'framework@npm:2.0.0' };
		fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
		const sbom = result(test);
		expect(edge(sbom, 'plugin@1.0.0', 'framework@1.0.0')).to.be.true;
		expect(edge(sbom, 'plugin@1.0.0', 'framework@2.0.0')).to.be.true;
	});

	test('Berry retains a peer provider’s own peer context', () => {
		const test = fixture('yarn-berry', { name: 'app', version: '1.0.0', dependencies: { first: '^1.0.0', second: '^1.0.0' } }, {
			first: { version: '1.0.0', dependencies: { plugin: '^1.0.0', adapter: '^1.0.0', framework: '^1.0.0' } },
			second: { version: '1.0.0', dependencies: { plugin: '^1.0.0', adapter: '^1.0.0', framework: '^2.0.0' } },
			plugin: { version: '1.0.0', peerDependencies: { adapter: '*' } },
			adapter: { version: '1.0.0', peerDependencies: { framework: '*' } }, framework: { version: '1.0.0' },
		});
		test.lock['framework@npm:^2.0.0'] = { version: '2.0.0', resolution: 'framework@npm:2.0.0' };
		fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
		const sbom = result(test);
		expect(edge(sbom, 'plugin@1.0.0', 'adapter@1.0.0')).to.be.true;
		expect(edge(sbom, 'adapter@1.0.0', 'framework@1.0.0')).to.be.true;
		expect(edge(sbom, 'adapter@1.0.0', 'framework@2.0.0')).to.be.true;
	});

	test('Berry reads local portal manifests without installing them', () => {
		const test = fixture('yarn-berry', { name: 'app', version: '1.0.0', dependencies: { local: 'portal:local' } }, { alpha: { version: '1.0.0' } });
		const local = { name: 'local', version: '2.0.0', dependencies: { alpha: '^1.0.0' } };
		fs.mkdirSync(path.join(root, 'local'));
		fs.writeFileSync(path.join(root, 'local', 'package.json'), JSON.stringify(local));
		test.lock['local@portal:local'] = { version: '0.0.0-use.local', resolution: 'local@portal:local', dependencies: { alpha: 'npm:^1.0.0' } };
		fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
		const before = snapshot(root);
		expect(edge(result(test), 'local@2.0.0', 'alpha@1.0.0')).to.be.true;
		expect(snapshot(root)).to.deep.equal(before);
		local.dependencies.alpha = '^2.0.0';
		fs.writeFileSync(path.join(root, 'local', 'package.json'), JSON.stringify(local));
		expect(() => result(test)).to.throw(/out of date.*alpha/);
	});

	for (const manager of ['yarn-classic', 'yarn-berry']) {
		test(`${manager} validates directory file dependencies without including their development dependencies`, () => {
			const test = fixture(manager, { name: 'app', version: '1.0.0', dependencies: { local: 'file:local' } }, { alpha: { version: '1.0.0' } });
			const local = { name: 'local', version: '2.0.0', dependencies: { alpha: '^1.0.0' }, devDependencies: { dev: '^1.0.0' } };
			fs.mkdirSync(path.join(root, 'local'));
			fs.writeFileSync(path.join(root, 'local', 'package.json'), JSON.stringify(local));
			test.lock['local@file:local'] = { version: '2.0.0', ...(manager === 'yarn-berry' ? { resolution: 'local@file:local' } : {}), dependencies: { alpha: '^1.0.0' } };
			fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
			const before = snapshot(root);
			expect(edge(result(test), 'local@2.0.0', 'alpha@1.0.0')).to.be.true;
			expect(snapshot(root)).to.deep.equal(before);
			local.dependencies.alpha = '^2.0.0';
			fs.writeFileSync(path.join(root, 'local', 'package.json'), JSON.stringify(local));
			expect(() => result(test)).to.throw(/out of date.*alpha/);
		});
	}

	test('Classic aliases retain canonical identity and hashes', () => {
		const test = fixture('yarn-classic', { name: 'app', version: '1.0.0', dependencies: { alias: 'npm:real@^1.0.0' } }, {});
		test.lock['alias@npm:real@^1.0.0'] = { version: '1.0.0', integrity: `sha512-${Buffer.from('ab'.repeat(64), 'hex').toString('base64')}` };
		fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
		for (const { method } of SBOM_CASES) {
			const component = result(test, method).components[0];
			expect(component.purl).to.equal('pkg:npm/real@1.0.0');
			expect(component.hashes).to.deep.equal([{ alg: 'SHA-512', content: 'ab'.repeat(64) }]);
		}
	});

	test('Berry registry patches retain the original package name and checksum', () => {
		const test = fixture('yarn-berry', undefined, { alpha: { version: '1.0.0', checksum: `10c0/${'ab'.repeat(64)}` } });
		test.lock['alpha@npm:^1.0.0'].resolution = 'alpha@patch:alpha@npm%3A1.0.0#builtin<compat/alpha>';
		fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
		const alpha = result(test).components.find(c => c.name === 'alpha');
		expect(alpha.purl).to.equal('pkg:npm/alpha@1.0.0');
		expect(alpha.hashes).to.deep.equal([{ alg: 'SHA-512', content: 'ab'.repeat(64) }]);
	});

	test('Berry refuses unknown protocols and missing package identities', () => {
		const test = fixture('yarn-berry');
		test.lock['alpha@npm:^1.0.0'].resolution = 'alpha@custom:1.0.0';
		fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
		expect(() => result(test)).to.throw(/Unsupported.*unknown resolution protocol/);
	});

	test('Classic resolves each combined selector without confusing duplicate versions', () => {
		const test = fixture('yarn-classic', { name: 'app', version: '1.0.0', dependencies: { alpha: '^1.0.0', other: '^1.0.0' } }, {
			alpha: { version: '1.0.0', dependencies: { shared: '^1.0.0' } }, other: { version: '1.0.0', dependencies: { shared: '^2.0.0' } },
		});
		test.lock['shared@^1.0.0, shared@~1.0.0'] = { version: '1.0.0' };
		test.lock['shared@^2.0.0'] = { version: '2.0.0' };
		fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
		const sbom = result(test);
		expect(edge(sbom, 'alpha@1.0.0', 'shared@1.0.0')).to.be.true;
		expect(edge(sbom, 'other@1.0.0', 'shared@2.0.0')).to.be.true;
	});
});

suite('complete JavaScript SBOM reference comparisons', () => {
	let clock;
	suiteSetup(() => { clock = useFakeTimers(new Date('2023-08-07T00:00:00.000Z')); });
	suiteTeardown(() => { clock.restore(); });
	for (const manager of MANAGERS) {
		const base = `test/providers/tst_manifests/${manager}`;
		const fixtures = ['package_json_deps_without_exhortignore_object', 'package_json_deps_with_exhortignore_object', 'package_json_deps_with_mixed_dep_types', ...(manager === 'yarn-classic' ? [] : ['workspace_member'])];
		for (const fixture of fixtures) {
			for (const { method, type } of SBOM_CASES) {
				test(`${manager} ${fixture} ${type} matches every SBOM field`, () => {
					const dir = `${base}/${fixture}`;
					const manifest = `${dir}/${fixture === 'workspace_member' ? 'packages/member-a/package.json' : 'package.json'}`;
					const provider = manager === 'npm' ? new Npm() : new Yarn();
					const actual = provider[method](manifest);
					const expected = JSON.parse(fs.readFileSync(`${dir}/expected_${type}_sbom.json`, 'utf8'));
					expected.metadata.tools.components[0].version = getPackageVersion();
					expect(actual.contentType).to.equal('application/vnd.cyclonedx+json');
					expect(canonical(actual.content)).to.deep.equal(canonical(expected));
				});
			}
		}
	}
});
