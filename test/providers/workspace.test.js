import fs from 'node:fs'
import path from 'node:path'

import { expect } from 'chai'
import esmock from 'esmock'

import {
	discoverUvWorkspaceMembers,
	discoverWorkspaceCrates,
	discoverWorkspacePackages,
	filterManifestPathsByDiscoveryIgnore,
	resolveWorkspaceDiscoveryIgnore,
	validatePackageJson,
} from '../../src/workspace.js'

suite('discoverWorkspacePackages', () => {
	test('returns empty when no pnpm-workspace.yaml or package.json workspaces', async () => {
		const root = 'test/providers/tst_manifests/npm/package_json_deps_without_exhortignore_object'
		const result = await discoverWorkspacePackages(root)
		expect(result).to.be.an('array')
		expect(result).to.have.lengthOf(0)
	})

	test('excludes paths matching workspaceDiscoveryIgnore', async () => {
		const pkgContent = { name: 'root', version: '1.0.0', workspaces: ['packages/*'] }
		const memberA = { name: 'a', version: '1.0.0' }
		const memberB = { name: 'b', version: '1.0.0' }
		const tmpDir = path.join(process.cwd(), 'test/providers/tst_manifests/tmp_workspace_ignore')
		fs.mkdirSync(path.join(tmpDir, 'packages/a'), { recursive: true })
		fs.mkdirSync(path.join(tmpDir, 'packages/b'), { recursive: true })
		fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify(pkgContent))
		fs.writeFileSync(path.join(tmpDir, 'packages/a/package.json'), JSON.stringify(memberA))
		fs.writeFileSync(path.join(tmpDir, 'packages/b/package.json'), JSON.stringify(memberB))
		try {
			const result = await discoverWorkspacePackages(tmpDir, {
				workspaceDiscoveryIgnore: ['**/packages/b/**'],
			})
			expect(result.some(p => p.endsWith('packages/a/package.json'))).to.be.true
			expect(result.some(p => p.endsWith('packages/b/package.json'))).to.be.false
		} finally {
			fs.rmSync(tmpDir, { recursive: true, force: true })
		}
	})

	test('discovers packages from package.json workspaces array', async () => {
		const pkgContent = { name: 'root', version: '1.0.0', workspaces: ['packages/*'] }
		const memberPkg = { name: 'member', version: '1.0.0' }
		const tmpDir = path.join(process.cwd(), 'test/providers/tst_manifests/tmp_workspace_test')
		fs.mkdirSync(path.join(tmpDir, 'packages/member'), { recursive: true })
		fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify(pkgContent))
		fs.writeFileSync(path.join(tmpDir, 'packages/member/package.json'), JSON.stringify(memberPkg))
		try {
			const result = await discoverWorkspacePackages(tmpDir)
			expect(result).to.be.an('array')
			expect(result.length).to.be.at.least(1)
			expect(result.some(p => p.endsWith('packages/member/package.json'))).to.be.true
		} finally {
			fs.rmSync(tmpDir, { recursive: true, force: true })
		}
	})

	test('returns empty when package.json has no workspaces (single package)', async () => {
		const root = 'test/providers/provider_manifests/npm/with_lock_file'
		const result = await discoverWorkspacePackages(root)
		expect(result).to.be.an('array')
		expect(result).to.have.lengthOf(0)
	})
})

suite('resolveWorkspaceDiscoveryIgnore', () => {
	test('merges defaults with opts and dedupes', () => {
		const r = resolveWorkspaceDiscoveryIgnore({
			workspaceDiscoveryIgnore: ['**/vendor/**', '**/node_modules/**'],
		})
		expect(r).to.include('**/node_modules/**')
		expect(r).to.include('**/.git/**')
		expect(r).to.include('**/vendor/**')
	})
})

suite('filterManifestPathsByDiscoveryIgnore', () => {
	test('removes paths matching a pattern', () => {
		const root = path.resolve('test/providers/tst_manifests')
		const paths = [
			path.join(root, 'a/package.json'),
			path.join(root, 'node_modules/x/package.json'),
		]
		const filtered = filterManifestPathsByDiscoveryIgnore(paths, root, ['**/node_modules/**'])
		expect(filtered).to.have.lengthOf(1)
		expect(filtered[0]).to.include('a/package.json')
	})
})

suite('validatePackageJson', () => {
	test('accepts valid name and version', () => {
		const tmpDir = path.join(process.cwd(), 'test/providers/tst_manifests/tmp_validate_pkg')
		fs.mkdirSync(tmpDir, { recursive: true })
		const p = path.join(tmpDir, 'package.json')
		fs.writeFileSync(p, JSON.stringify({ name: 'foo', version: '1.0.0' }))
		try {
			const r = validatePackageJson(p)
			expect(r.valid).to.be.true
			if (r.valid) {
				expect(r.name).to.equal('foo')
				expect(r.version).to.equal('1.0.0')
			}
		} finally {
			fs.rmSync(tmpDir, { recursive: true, force: true })
		}
	})

	test('rejects missing name', () => {
		const tmpDir = path.join(process.cwd(), 'test/providers/tst_manifests/tmp_validate_pkg2')
		fs.mkdirSync(tmpDir, { recursive: true })
		const p = path.join(tmpDir, 'package.json')
		fs.writeFileSync(p, JSON.stringify({ version: '1.0.0' }))
		try {
			const r = validatePackageJson(p)
			expect(r.valid).to.be.false
			if (!r.valid) {
				expect(r.error).to.match(/name/i)
			}
		} finally {
			fs.rmSync(tmpDir, { recursive: true, force: true })
		}
	})

	test('rejects missing version', () => {
		const tmpDir = path.join(process.cwd(), 'test/providers/tst_manifests/tmp_validate_pkg3')
		fs.mkdirSync(tmpDir, { recursive: true })
		const p = path.join(tmpDir, 'package.json')
		fs.writeFileSync(p, JSON.stringify({ name: 'foo' }))
		try {
			const r = validatePackageJson(p)
			expect(r.valid).to.be.false
			if (!r.valid) {
				expect(r.error).to.match(/version/i)
			}
		} finally {
			fs.rmSync(tmpDir, { recursive: true, force: true })
		}
	})

	test('rejects invalid JSON', () => {
		const tmpDir = path.join(process.cwd(), 'test/providers/tst_manifests/tmp_validate_pkg4')
		fs.mkdirSync(tmpDir, { recursive: true })
		const p = path.join(tmpDir, 'package.json')
		fs.writeFileSync(p, '{ not json')
		try {
			const r = validatePackageJson(p)
			expect(r.valid).to.be.false
			if (!r.valid) {
				expect(r.error).to.match(/Invalid package\.json/i)
			}
		} finally {
			fs.rmSync(tmpDir, { recursive: true, force: true })
		}
	})
})

suite('discoverWorkspaceCrates', () => {
	test('returns empty when no Cargo.toml or Cargo.lock at root', async () => {
		const result = await discoverWorkspaceCrates('test/providers/tst_manifests/npm')
		expect(result).to.be.an('array')
		expect(result).to.have.lengthOf(0)
	})

	test('discovers workspace members from Cargo workspace', async () => {
		const root = path.resolve('test/providers/tst_manifests/cargo/cargo_virtual_workspace')
		const metadata = {
			packages: [
				{ id: `path+file://${root}/crate-a#0.1.0`, manifest_path: path.join(root, 'crate-a/Cargo.toml') },
				{ id: `path+file://${root}/crate-b#0.2.0`, manifest_path: path.join(root, 'crate-b/Cargo.toml') }
			],
			workspace_members: [`path+file://${root}/crate-a#0.1.0`, `path+file://${root}/crate-b#0.2.0`]
		}
		const { discoverWorkspaceCrates } = await esmock('../../src/workspace.js', {
			'../../src/tools.js': {
				getCustomPath: () => 'cargo',
				invokeCommand: () => Buffer.from(JSON.stringify(metadata))
			}
		})
		const result = await discoverWorkspaceCrates(root)
		expect(result).to.be.an('array')
		expect(result).to.have.lengthOf(2)
		expect(result.every(p => p.endsWith('Cargo.toml'))).to.be.true
		expect(result.some(p => p.includes('crate-a'))).to.be.true
		expect(result.some(p => p.includes('crate-b'))).to.be.true
	})
})

suite('discoverUvWorkspaceMembers', () => {
	test('returns empty when no pyproject.toml at root', async () => {
		const result = await discoverUvWorkspaceMembers('test/providers/tst_manifests/npm')
		expect(result).to.be.an('array')
		expect(result).to.have.lengthOf(0)
	})

	test('returns empty when pyproject.toml exists but no uv.lock', async () => {
		const root = path.resolve('test/providers/tst_manifests/pyproject/uv_workspace_no_lock')
		const result = await discoverUvWorkspaceMembers(root)
		expect(result).to.be.an('array')
		expect(result).to.have.lengthOf(0)
	})

	test('returns empty when pyproject.toml has no [tool.uv.workspace]', async () => {
		const root = path.resolve('test/providers/tst_manifests/pyproject/uv_workspace_no_config')
		const result = await discoverUvWorkspaceMembers(root)
		expect(result).to.be.an('array')
		expect(result).to.have.lengthOf(0)
	})

	test('discovers members from root-package workspace (includes root)', async () => {
		const root = path.resolve('test/providers/tst_manifests/pyproject/uv_workspace')
		const result = await discoverUvWorkspaceMembers(root)
		expect(result).to.be.an('array')
		expect(result).to.have.lengthOf(3)
		expect(result.every(p => p.endsWith('pyproject.toml'))).to.be.true
		expect(result[0]).to.equal(path.join(root, 'pyproject.toml'))
		expect(result.some(p => p.includes(path.join('packages', 'mid-pkg')))).to.be.true
		expect(result.some(p => p.includes(path.join('packages', 'sub-pkg')))).to.be.true
	})

	test('discovers members from virtual workspace (excludes root)', async () => {
		const root = path.resolve('test/providers/tst_manifests/pyproject/uv_workspace_virtual')
		const result = await discoverUvWorkspaceMembers(root)
		expect(result).to.be.an('array')
		expect(result).to.have.lengthOf(2)
		expect(result.every(p => p.endsWith('pyproject.toml'))).to.be.true
		expect(result.some(p => p.includes(path.join('packages', 'pkg-a')))).to.be.true
		expect(result.some(p => p.includes(path.join('packages', 'pkg-b')))).to.be.true
		expect(result.every(p => p !== path.join(root, 'pyproject.toml'))).to.be.true
	})

	test('respects exclude patterns', async () => {
		const root = path.resolve('test/providers/tst_manifests/pyproject/uv_workspace_exclude')
		const result = await discoverUvWorkspaceMembers(root)
		expect(result.some(p => p.includes(path.join('packages', 'core')))).to.be.true
		expect(result.some(p => p.includes(path.join('packages', 'internal')))).to.be.false
	})

	test('discovers members from multiple glob patterns', async () => {
		const root = path.resolve('test/providers/tst_manifests/pyproject/uv_workspace_nested')
		const result = await discoverUvWorkspaceMembers(root)
		expect(result).to.be.an('array')
		expect(result.some(p => p.includes(path.join('apps', 'backend')))).to.be.true
		expect(result.some(p => p.includes(path.join('libs', 'core')))).to.be.true
	})

	test('applies workspaceDiscoveryIgnore patterns', async () => {
		const root = path.resolve('test/providers/tst_manifests/pyproject/uv_workspace_nested')
		const result = await discoverUvWorkspaceMembers(root, {
			workspaceDiscoveryIgnore: ['**/libs/**'],
		})
		expect(result.some(p => p.includes(path.join('apps', 'backend')))).to.be.true
		expect(result.some(p => p.includes(path.join('libs', 'core')))).to.be.false
	})
})
