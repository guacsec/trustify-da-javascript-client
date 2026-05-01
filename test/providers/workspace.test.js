import fs from 'node:fs'
import path from 'node:path'

import { expect } from 'chai'
import esmock from 'esmock'

import { discoverGoWorkspaceModules } from '../../src/providers/golang_gomodules.js'
import { discoverGradleSubprojects } from '../../src/providers/java_gradle.js'
import { discoverMavenModules } from '../../src/providers/java_maven.js'
import { discoverUvWorkspaceMembers } from '../../src/providers/python_uv.js'
import {
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

suite('discoverGradleSubprojects', () => {
	test('returns empty when no settings.gradle at root', async () => {
		const result = await discoverGradleSubprojects('test/providers/tst_manifests/npm')
		expect(result).to.be.an('array')
		expect(result).to.have.lengthOf(0)
	})
	test('discovers multi-project build', async () => {
		const root = path.resolve('test/providers/tst_manifests/gradle/gradle_multi_project')
		const result = await discoverGradleSubprojects(root)
		expect(result).to.be.an('array')
		expect(result).to.have.lengthOf(3)
		expect(result[0]).to.equal(path.join(root, 'build.gradle'))
		expect(result.some(p => p.includes(path.join('app', 'build.gradle')))).to.be.true
		expect(result.some(p => p.includes(path.join('lib', 'build.gradle')))).to.be.true
	}).timeout(40000)

	test('discovers nested subprojects', async () => {
		const root = path.resolve('test/providers/tst_manifests/gradle/gradle_nested_subprojects')
		const result = await discoverGradleSubprojects(root)
		expect(result).to.be.an('array')
		expect(result).to.have.lengthOf(3)
		expect(result[0]).to.equal(path.join(root, 'build.gradle'))
		expect(result.some(p => p.includes(path.join('libs', 'core', 'build.gradle')))).to.be.true
		expect(result.some(p => p.includes(path.join('libs', 'util', 'build.gradle')))).to.be.true
	}).timeout(40000)

	test('handles mixed Groovy and Kotlin build files', async () => {
		const root = path.resolve('test/providers/tst_manifests/gradle/gradle_mixed_variants')
		const result = await discoverGradleSubprojects(root)
		expect(result).to.be.an('array')
		expect(result).to.have.lengthOf(3)
		expect(result[0]).to.equal(path.join(root, 'build.gradle.kts'))
		expect(result.some(p => p.endsWith(path.join('app', 'build.gradle')))).to.be.true
		expect(result.some(p => p.endsWith(path.join('lib', 'build.gradle.kts')))).to.be.true
	}).timeout(40000)

	test('returns root only when no subprojects', async () => {
		const root = path.resolve('test/providers/tst_manifests/gradle/gradle_no_subprojects')
		const result = await discoverGradleSubprojects(root)
		expect(result).to.be.an('array')
		expect(result).to.have.lengthOf(1)
		expect(result[0]).to.equal(path.join(root, 'build.gradle'))
	}).timeout(40000)

	test('returns root build file when gradle is not available', async () => {
		const root = path.resolve('test/providers/tst_manifests/gradle/gradle_multi_project')
		const { discoverGradleSubprojects: discoverMocked } = await esmock('../../src/providers/java_gradle.js', {
			'../../src/tools.js': {
				getCustomPath: () => '/nonexistent/gradle',
				getWrapperPreference: () => false,
				invokeCommand: () => { throw Object.assign(new Error('gradle not found'), { code: 'ENOENT' }) },
			},
		})
		const result = await discoverMocked(root)
		expect(result).to.be.an('array')
		expect(result).to.have.lengthOf(1)
		expect(result[0]).to.equal(path.join(root, 'build.gradle'))
	})

	test('excludes paths matching workspaceDiscoveryIgnore', async () => {
		const root = path.resolve('test/providers/tst_manifests/gradle/gradle_multi_project')
		const result = await discoverGradleSubprojects(root, {
			workspaceDiscoveryIgnore: ['**/lib/**'],
		})
		expect(result.some(p => p.includes(path.join('app', 'build.gradle')))).to.be.true
		expect(result.some(p => p.includes(path.join('lib', 'build.gradle')))).to.be.false
	}).timeout(40000)
})

suite('discoverMavenModules', () => {
	test('returns empty when no pom.xml at root', async () => {
		const result = await discoverMavenModules('test/providers/tst_manifests/npm')
		expect(result).to.be.an('array')
		expect(result).to.have.lengthOf(0)
	})

	test('returns root pom only when mvn reports no modules', async () => {
		const root = path.resolve('test/providers/tst_manifests/maven/maven_no_modules')
		const result = await discoverMavenModules(root)
		expect(result).to.be.an('array')
		expect(result).to.have.lengthOf(1)
		expect(result[0]).to.equal(path.join(root, 'pom.xml'))
	}).timeout(40000)

	test('discovers multi-module project', async () => {
		const root = path.resolve('test/providers/tst_manifests/maven/maven_multi_module')
		const result = await discoverMavenModules(root)
		expect(result).to.be.an('array')
		expect(result).to.have.lengthOf(3)
		expect(result.every(p => p.endsWith('pom.xml'))).to.be.true
		expect(result[0]).to.equal(path.join(root, 'pom.xml'))
		expect(result.some(p => p.includes('module-a'))).to.be.true
		expect(result.some(p => p.includes('module-b'))).to.be.true
	}).timeout(40000)

	test('discovers nested aggregator modules recursively', async () => {
		const root = path.resolve('test/providers/tst_manifests/maven/maven_nested_aggregator')
		const result = await discoverMavenModules(root)
		expect(result).to.be.an('array')
		expect(result).to.have.lengthOf(3)
		expect(result[0]).to.equal(path.join(root, 'pom.xml'))
		expect(result.some(p => p.includes(path.join('parent', 'pom.xml')))).to.be.true
		expect(result.some(p => p.includes(path.join('parent', 'child', 'pom.xml')))).to.be.true
	}).timeout(40000)

	test('returns root pom when mvn is not available', async () => {
		const root = path.resolve('test/providers/tst_manifests/maven/maven_multi_module')
		const { discoverMavenModules: discoverMocked } = await esmock('../../src/providers/java_maven.js', {
			'../../src/tools.js': {
				getCustomPath: () => '/nonexistent/mvn',
				getWrapperPreference: () => false,
				invokeCommand: () => { throw Object.assign(new Error('mvn not found'), { code: 'ENOENT' }) },
			},
		})
		const result = await discoverMocked(root)
		expect(result).to.be.an('array')
		expect(result).to.have.lengthOf(1)
		expect(result[0]).to.equal(path.join(root, 'pom.xml'))
	})

	test('excludes paths matching workspaceDiscoveryIgnore', async () => {
		const root = path.resolve('test/providers/tst_manifests/maven/maven_multi_module')
		const result = await discoverMavenModules(root, {
			workspaceDiscoveryIgnore: ['**/module-b/**'],
		})
		expect(result.some(p => p.includes('module-a'))).to.be.true
		expect(result.some(p => p.includes('module-b'))).to.be.false
	}).timeout(40000)
})

suite('discoverGoWorkspaceModules', () => {
	test('returns empty when no go.work at root', async () => {
		const result = await discoverGoWorkspaceModules('test/providers/tst_manifests/npm')
		expect(result).to.be.an('array')
		expect(result).to.have.lengthOf(0)
	})

	test('discovers modules from go.work with two modules', async () => {
		const root = path.resolve('test/providers/tst_manifests/golang/go_workspace')
		const result = await discoverGoWorkspaceModules(root)
		expect(result).to.be.an('array')
		expect(result).to.have.lengthOf(2)
		expect(result.every(p => p.endsWith('go.mod'))).to.be.true
		expect(result.some(p => p.includes('module-a'))).to.be.true
		expect(result.some(p => p.includes('module-b'))).to.be.true
	})

	test('discovers modules from nested directories', async () => {
		const root = path.resolve('test/providers/tst_manifests/golang/go_workspace_nested')
		const result = await discoverGoWorkspaceModules(root)
		expect(result).to.have.lengthOf(2)
		expect(result.some(p => p.includes(path.join('libs', 'core', 'go.mod')))).to.be.true
		expect(result.some(p => p.includes(path.join('libs', 'util', 'go.mod')))).to.be.true
	})

	test('discovers single module', async () => {
		const root = path.resolve('test/providers/tst_manifests/golang/go_workspace_single')
		const result = await discoverGoWorkspaceModules(root)
		expect(result).to.have.lengthOf(1)
		expect(result[0]).to.include(path.join('mymod', 'go.mod'))
	})

	test('skips modules whose directory does not exist', async () => {
		const root = path.resolve('test/providers/tst_manifests/golang/go_workspace_missing_module')
		const result = await discoverGoWorkspaceModules(root)
		expect(result).to.have.lengthOf(1)
		expect(result[0]).to.include(path.join('existing', 'go.mod'))
	})

	test('returns empty when go command fails', async () => {
		const root = path.resolve('test/providers/tst_manifests/golang/go_workspace')
		const { discoverGoWorkspaceModules: discoverMocked } = await esmock('../../src/providers/golang_gomodules.js', {
			'../../src/tools.js': {
				getCustom: () => null,
				getCustomPath: () => 'go',
				invokeCommand: () => { throw new Error('go not found') },
			},
		})
		const result = await discoverMocked(root)
		expect(result).to.have.lengthOf(0)
	})

	test('returns empty when go output is invalid JSON', async () => {
		const root = path.resolve('test/providers/tst_manifests/golang/go_workspace')
		const { discoverGoWorkspaceModules: discoverMocked } = await esmock('../../src/providers/golang_gomodules.js', {
			'../../src/tools.js': {
				getCustom: () => null,
				getCustomPath: () => 'go',
				invokeCommand: () => Buffer.from('not json'),
			},
		})
		const result = await discoverMocked(root)
		expect(result).to.have.lengthOf(0)
	})

	test('returns empty when Use is null (no use directives)', async () => {
		const root = path.resolve('test/providers/tst_manifests/golang/go_workspace_empty')
		const result = await discoverGoWorkspaceModules(root)
		expect(result).to.have.lengthOf(0)
	})

	test('applies ignore patterns to discovered modules', async () => {
		const root = path.resolve('test/providers/tst_manifests/golang/go_workspace_nested')
		const result = await discoverGoWorkspaceModules(root, {
			workspaceDiscoveryIgnore: ['**/util/**'],
		})
		expect(result.some(p => p.includes(path.join('libs', 'core', 'go.mod')))).to.be.true
		expect(result.some(p => p.includes(path.join('libs', 'util', 'go.mod')))).to.be.false
	})
})
