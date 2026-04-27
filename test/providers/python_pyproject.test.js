import fs from 'fs'
import path from 'path'

import { expect } from 'chai'
import { useFakeTimers } from 'sinon'

import Python_pip_pyproject from '../../src/providers/python_pip_pyproject.js'
import Python_poetry from '../../src/providers/python_poetry.js'
import Python_uv from '../../src/providers/python_uv.js'

let clock
let originalPlatform

const TIMEOUT = process.env.GITHUB_ACTIONS ? 30000 : 15000

const uvProvider = new Python_uv()
const poetryProvider = new Python_poetry()
const pipProvider = new Python_pip_pyproject()

const MANIFESTS = 'test/providers/tst_manifests/pyproject'

const SBOM_CASES = [
	{type: 'stack', method: 'provideStack', fixture: 'expected_stack_sbom.json'},
	{type: 'component', method: 'provideComponent', fixture: 'expected_component_sbom.json'},
]

suite('testing the python-pyproject data provider', () => {
	/** Verifies isSupported correctly identifies pyproject.toml manifests. */
	[
		{name: 'pyproject.toml', expected: true},
		{name: 'requirements.txt', expected: false},
		{name: 'Cargo.toml', expected: false},
	].forEach(testCase => {
		test(`verify isSupported returns ${testCase.expected} for ${testCase.name}`, () =>
			expect(uvProvider.isSupported(testCase.name)).to.equal(testCase.expected)
		)
	});

	/** Verifies each provider's validateLockFile detects or rejects its lock file. */
	[
		{provider: uvProvider, name: 'uv', dir: 'uv_lock', expected: true},
		{provider: uvProvider, name: 'uv', dir: 'poetry_lock', expected: false},
		{provider: poetryProvider, name: 'poetry', dir: 'poetry_lock', expected: true},
		{provider: poetryProvider, name: 'poetry', dir: 'uv_lock', expected: false},
	].forEach(({provider, name, dir, expected}) => {
		test(`verify ${name} validateLockFile returns ${expected} for ${dir}`, () => {
			expect(provider.validateLockFile(`${MANIFESTS}/${dir}`)).to.equal(expected)
		})
	})

	suite('uv projects (via uv export)', () => {
		const fixtureDir = `${MANIFESTS}/pep621_ignore_and_extras`

		/** Verifies stack and component SBOM output matches expected fixtures. */
		SBOM_CASES.forEach(({type, method, fixture}) => {
			test(`verify pyproject.toml sbom provided for ${type} analysis with uv`, async () => {
				let expectedSbom = fs.readFileSync(path.join(fixtureDir, fixture)).toString().trim()
				expectedSbom = JSON.stringify(JSON.parse(expectedSbom))
				let result = await uvProvider[method](path.join(fixtureDir, 'pyproject.toml'))
				expect(result).to.deep.equal({
					ecosystem: 'pip',
					contentType: 'application/vnd.cyclonedx+json',
					content: expectedSbom
				})
			}).timeout(TIMEOUT)
		})

		/** Verifies exhortignore and trustify-da-ignore markers exclude deps from component analysis. */
		test('exhortignore and trustify-da-ignore exclude deps from component analysis', async () => {
			let result = await uvProvider.provideComponent(path.join(fixtureDir, 'pyproject.toml'))
			let sbom = JSON.parse(result.content)
			let names = sbom.components.map(c => c.name)
			expect(names).to.not.include('uvicorn')
			expect(names).to.not.include('markupsafe')
			expect(names).to.include('flask')
			expect(names).to.include('requests')
		}).timeout(TIMEOUT)

		/** Verifies ignored transitive deps are pruned from the stack dependency tree. */
		test('ignored transitive dep excluded from stack analysis tree', async () => {
			let result = await uvProvider.provideStack(path.join(fixtureDir, 'pyproject.toml'))
			let sbom = JSON.parse(result.content)
			let names = sbom.components.map(c => c.name)
			expect(names).to.not.include('uvicorn')
			expect(names).to.not.include('markupsafe')
			let jinja2Dep = sbom.dependencies.find(d => d.ref.includes('/jinja2@'))
			expect(jinja2Dep).to.exist
			expect(jinja2Dep.dependsOn).to.deep.equal([])
		}).timeout(TIMEOUT)

		/** Verifies name canonicalization normalizes underscores to hyphens. */
		test('name canonicalization: typing_extensions matches typing-extensions', async () => {
			let result = await uvProvider.provideComponent(path.join(fixtureDir, 'pyproject.toml'))
			let sbom = JSON.parse(result.content)
			let typingExt = sbom.components.find(c => c.name === 'typing-extensions')
			expect(typingExt).to.exist
			expect(typingExt.version).to.equal('4.1.1')
		}).timeout(TIMEOUT)
	})

	suite('uv projects - dev dependencies excluded (TC-4096)', () => {
		test('dev dependencies excluded from stack analysis', async () => {
			let expectedSbom = fs.readFileSync('test/providers/tst_manifests/pyproject/uv_dev_deps/expected_stack_sbom.json').toString()
			expectedSbom = JSON.stringify(JSON.parse(expectedSbom))
			let result = await uvProvider.provideStack('test/providers/tst_manifests/pyproject/uv_dev_deps/pyproject.toml')
			expect(result).to.deep.equal({
				ecosystem: 'pip',
				contentType: 'application/vnd.cyclonedx+json',
				content: expectedSbom
			})
		}).timeout(TIMEOUT)

		test('dev dependencies excluded from component analysis', async () => {
			let expectedSbom = fs.readFileSync('test/providers/tst_manifests/pyproject/uv_dev_deps/expected_component_sbom.json').toString().trim()
			expectedSbom = JSON.stringify(JSON.parse(expectedSbom))
			let result = await uvProvider.provideComponent('test/providers/tst_manifests/pyproject/uv_dev_deps/pyproject.toml')
			expect(result).to.deep.equal({
				ecosystem: 'pip',
				contentType: 'application/vnd.cyclonedx+json',
				content: expectedSbom
			})
		}).timeout(TIMEOUT)
	})

	suite('uv projects - self-reference excluded (TC-4097)', () => {
		const fixtureDir = `${MANIFESTS}/uv_self_ref`

		/** Verifies stack and component SBOM output excludes the project itself. */
		SBOM_CASES.forEach(({type, method, fixture}) => {
			test(`project self-reference excluded from ${type} analysis`, async () => {
				let expectedSbom = fs.readFileSync(path.join(fixtureDir, fixture)).toString().trim()
				expectedSbom = JSON.stringify(JSON.parse(expectedSbom))
				let result = await uvProvider[method](path.join(fixtureDir, 'pyproject.toml'))
				expect(result).to.deep.equal({
					ecosystem: 'pip',
					contentType: 'application/vnd.cyclonedx+json',
					content: expectedSbom
				})
			}).timeout(TIMEOUT)
		})
	})

	suite('uv projects - uv_lock manifest', () => {
		const fixtureDir = `${MANIFESTS}/uv_lock`

		/** Verifies stack and component SBOM output matches expected fixtures. */
		SBOM_CASES.forEach(({type, method, fixture}) => {
			test(`verify pyproject.toml sbom provided for ${type} analysis with uv_lock`, async () => {
				let expectedSbom = fs.readFileSync(path.join(fixtureDir, fixture)).toString().trim()
				expectedSbom = JSON.stringify(JSON.parse(expectedSbom))
				let result = await uvProvider[method](path.join(fixtureDir, 'pyproject.toml'))
				expect(result).to.deep.equal({
					ecosystem: 'pip',
					contentType: 'application/vnd.cyclonedx+json',
					content: expectedSbom
				})
			}).timeout(TIMEOUT)
		})
	})

	suite('poetry projects (via poetry show)', () => {
		const fixtureDir = `${MANIFESTS}/poetry_lock`

		/** Verifies stack and component SBOM output matches expected fixtures. */
		SBOM_CASES.forEach(({type, method, fixture}) => {
			test(`verify pyproject.toml sbom provided for ${type} analysis with poetry`, async () => {
				let expectedSbom = fs.readFileSync(path.join(fixtureDir, fixture)).toString().trim()
				expectedSbom = JSON.stringify(JSON.parse(expectedSbom))
				let result = await poetryProvider[method](path.join(fixtureDir, 'pyproject.toml'))
				expect(result).to.deep.equal({
					ecosystem: 'pip',
					contentType: 'application/vnd.cyclonedx+json',
					content: expectedSbom
				})
			}).timeout(TIMEOUT)
		})

		/** Verifies resolved versions come from poetry show --all, not dependency constraints. */
		test('resolved versions come from poetry show --all, not constraints', async () => {
			let result = await poetryProvider.provideStack(path.join(fixtureDir, 'pyproject.toml'))
			let sbom = JSON.parse(result.content)
			let markupsafe = sbom.components.find(c => c.name === 'markupsafe')
			expect(markupsafe.version).to.equal('3.0.3')
			let urllib3 = sbom.components.find(c => c.name === 'urllib3')
			expect(urllib3.version).to.equal('2.6.3')
		}).timeout(TIMEOUT)

		/** Verifies exhortignore filtering excludes click and its exclusive transitive deps. */
		test('exhortignore filtering excludes click and its exclusive transitive deps', async () => {
			let result = await poetryProvider.provideStack(path.join(fixtureDir, 'pyproject.toml'))
			let sbom = JSON.parse(result.content)
			let names = sbom.components.map(c => c.name)
			expect(names).to.not.include('click')
			expect(names).to.include('flask')
			expect(names).to.include('requests')
		}).timeout(TIMEOUT)
	})

	suite('poetry projects - modern dev dependencies excluded (TC-4096)', () => {
		test('dev dependencies excluded from stack analysis', async () => {
			let expectedSbom = fs.readFileSync('test/providers/tst_manifests/pyproject/poetry_dev_deps/expected_stack_sbom.json').toString()
			expectedSbom = JSON.stringify(JSON.parse(expectedSbom))
			let result = await poetryProvider.provideStack('test/providers/tst_manifests/pyproject/poetry_dev_deps/pyproject.toml')
			expect(result).to.deep.equal({
				ecosystem: 'pip',
				contentType: 'application/vnd.cyclonedx+json',
				content: expectedSbom
			})
		}).timeout(TIMEOUT)

		test('dev dependencies excluded from component analysis', async () => {
			let expectedSbom = fs.readFileSync('test/providers/tst_manifests/pyproject/poetry_dev_deps/expected_component_sbom.json').toString().trim()
			expectedSbom = JSON.stringify(JSON.parse(expectedSbom))
			let result = await poetryProvider.provideComponent('test/providers/tst_manifests/pyproject/poetry_dev_deps/pyproject.toml')
			expect(result).to.deep.equal({
				ecosystem: 'pip',
				contentType: 'application/vnd.cyclonedx+json',
				content: expectedSbom
			})
		}).timeout(TIMEOUT)
	})

	suite('poetry projects - legacy dev-dependencies excluded (TC-4096)', () => {
		test('legacy dev dependencies excluded from stack analysis', async () => {
			let expectedSbom = fs.readFileSync('test/providers/tst_manifests/pyproject/poetry_legacy_dev_deps/expected_stack_sbom.json').toString()
			expectedSbom = JSON.stringify(JSON.parse(expectedSbom))
			let result = await poetryProvider.provideStack('test/providers/tst_manifests/pyproject/poetry_legacy_dev_deps/pyproject.toml')
			expect(result).to.deep.equal({
				ecosystem: 'pip',
				contentType: 'application/vnd.cyclonedx+json',
				content: expectedSbom
			})
		}).timeout(TIMEOUT)

		test('legacy dev dependencies excluded from component analysis', async () => {
			let expectedSbom = fs.readFileSync('test/providers/tst_manifests/pyproject/poetry_legacy_dev_deps/expected_component_sbom.json').toString().trim()
			expectedSbom = JSON.stringify(JSON.parse(expectedSbom))
			let result = await poetryProvider.provideComponent('test/providers/tst_manifests/pyproject/poetry_legacy_dev_deps/pyproject.toml')
			expect(result).to.deep.equal({
				ecosystem: 'pip',
				contentType: 'application/vnd.cyclonedx+json',
				content: expectedSbom
			})
		}).timeout(TIMEOUT)
	})

	suite('poetry projects - poetry_only_deps manifest', () => {
		const fixtureDir = `${MANIFESTS}/poetry_only_deps`

		/** Verifies stack and component SBOM output matches expected fixtures. */
		SBOM_CASES.forEach(({type, method, fixture}) => {
			test(`verify pyproject.toml sbom provided for ${type} analysis with poetry_only_deps`, async () => {
				let expectedSbom = fs.readFileSync(path.join(fixtureDir, fixture)).toString().trim()
				expectedSbom = JSON.stringify(JSON.parse(expectedSbom))
				let result = await poetryProvider[method](path.join(fixtureDir, 'pyproject.toml'))
				expect(result).to.deep.equal({
					ecosystem: 'pip',
					contentType: 'application/vnd.cyclonedx+json',
					content: expectedSbom
				})
			}).timeout(TIMEOUT)
		})
	})

	/** Verifies the pip provider's validateLockFile always returns true (fallback). */
	test('verify pip validateLockFile always returns true (fallback provider)', () => {
		expect(pipProvider.validateLockFile(`${MANIFESTS}/pip_pep621`)).to.equal(true)
		expect(pipProvider.validateLockFile('/nonexistent/dir')).to.equal(true)
	})

	suite('pip projects (via pip --dry-run --report)', () => {
		const pipFixtureDir = `${MANIFESTS}/pip_pep621`
		const pipIgnoreDir = `${MANIFESTS}/pip_pep621_ignore`

		/** Verifies stack and component SBOM output matches expected pip fixtures. */
		SBOM_CASES.forEach(({type, method, fixture}) => {
			test(`verify pyproject.toml sbom provided for ${type} analysis with pip`, async () => {
				let expectedSbom = fs.readFileSync(path.join(pipFixtureDir, fixture)).toString().trim()
				expectedSbom = JSON.stringify(JSON.parse(expectedSbom))
				let result = await pipProvider[method](path.join(pipFixtureDir, 'pyproject.toml'))
				expect(result).to.deep.equal({
					ecosystem: 'pip',
					contentType: 'application/vnd.cyclonedx+json',
					content: expectedSbom
				})
			}).timeout(TIMEOUT)
		})

		/** Verifies direct and transitive deps are correctly classified in stack SBOM. */
		test('stack analysis classifies direct and transitive dependencies correctly', async () => {
			let result = await pipProvider.provideStack(path.join(pipFixtureDir, 'pyproject.toml'))
			let sbom = JSON.parse(result.content)
			let rootDep = sbom.dependencies.find(d => d.ref.includes('/test-project@'))
			let directNames = rootDep.dependsOn.map(d => d.split('/').pop().split('@')[0])
			expect(directNames).to.include('requests')
			expect(directNames).to.include('charset-normalizer')
			expect(directNames).to.include('idna')
			expect(directNames).to.include('urllib3')
			expect(directNames).to.include('certifi')
			expect(directNames).to.include('pysocks')
			let requestsDep = sbom.dependencies.find(d => d.ref.includes('/requests@'))
			let reqTransNames = requestsDep.dependsOn.map(d => d.split('/').pop().split('@')[0])
			expect(reqTransNames).to.include('certifi')
			expect(reqTransNames).to.include('charset-normalizer')
			expect(reqTransNames).to.include('idna')
			expect(reqTransNames).to.include('urllib3')
		}).timeout(TIMEOUT)

		/** Verifies exhortignore marker produces expected SBOM for stack and component analysis. */
		SBOM_CASES.forEach(({type, method, fixture}) => {
			test(`verify exhortignore produces expected sbom for ${type} analysis with pip`, async () => {
				let expectedSbom = fs.readFileSync(path.join(pipIgnoreDir, fixture)).toString().trim()
				expectedSbom = JSON.stringify(JSON.parse(expectedSbom))
				let result = await pipProvider[method](path.join(pipIgnoreDir, 'pyproject.toml'))
				expect(result).to.deep.equal({
					ecosystem: 'pip',
					contentType: 'application/vnd.cyclonedx+json',
					content: expectedSbom
				})
			}).timeout(TIMEOUT)
		})

		/** Verifies name canonicalization (charset_normalizer -> charset-normalizer). */
		test('name canonicalization: charset_normalizer resolved as charset-normalizer', async () => {
			let result = await pipProvider.provideStack(path.join(pipFixtureDir, 'pyproject.toml'))
			let sbom = JSON.parse(result.content)
			let pkg = sbom.components.find(c => c.name === 'charset-normalizer')
			expect(pkg).to.exist
			expect(pkg.version).to.equal('3.4.7')
		}).timeout(TIMEOUT)
	})

	/** Verifies uv and poetry validateLockFile returns false when no lock file is present. */
	test('validateLockFile returns false when no lock file is present', () => {
		let tmpDir = `${MANIFESTS}/no_lock_file_dummy`
		fs.mkdirSync(tmpDir, { recursive: true })
		fs.writeFileSync(`${tmpDir}/pyproject.toml`,
			'[project]\nname = "test"\nversion = "1.0.0"\ndependencies = ["requests>=2.0"]')
		try {
			expect(uvProvider.validateLockFile(tmpDir)).to.equal(false)
			expect(poetryProvider.validateLockFile(tmpDir)).to.equal(false)
		} finally {
			fs.rmSync(tmpDir, { recursive: true, force: true })
		}
	})

	suite('uv projects - PEP 508 marker filtering (TC-4042 reproducer)', () => {
		const fixtureDir = `${MANIFESTS}/uv_marker_filtering`

		function makeUvExport(markerLines) {
			let lines = [
				'click==8.3.1',
				'    # via marker-test',
				'six==1.16.0',
				'    # via marker-test',
			]
			for (let ml of markerLines) {
				lines.push(ml.line)
				lines.push(`    # via ${ml.via || 'click'}`)
			}
			return lines.join('\n')
		}

		function injectAndRun(uvExportContent, fn) {
			return async () => {
				process.env['TRUSTIFY_DA_UV_EXPORT'] = Buffer.from(uvExportContent).toString('base64')
				try { await fn() } finally { delete process.env['TRUSTIFY_DA_UV_EXPORT'] }
			}
		}

		const EXCLUDED_MARKERS = [
			{desc: 'sys_platform == win32', line: "colorama==0.4.6 ; sys_platform == 'win32'"},
			{desc: 'platform_system == Windows', line: "colorama==0.4.6 ; platform_system == 'Windows'"},
			{desc: 'os_name == nt', line: "colorama==0.4.6 ; os_name == 'nt'"},
			{desc: 'compound marker (win32 and python)', line: "colorama==0.4.6 ; sys_platform == 'win32' and python_version >= '3.8'"},
		]

		EXCLUDED_MARKERS.forEach(({desc, line}) => {
			test(`packages with non-matching marker excluded from stack: ${desc}`, injectAndRun(
				makeUvExport([{line}]),
				async () => {
					let result = await uvProvider.provideStack(path.join(fixtureDir, 'pyproject.toml'))
					let sbom = JSON.parse(result.content)
					let names = sbom.components.map(c => c.name)
					expect(names).to.include('click')
					expect(names).to.not.include('colorama',
						`colorama with marker "${desc}" should be excluded on this platform`)
				}
			)).timeout(TIMEOUT)
		})

		const INCLUDED_MARKERS = [
			{desc: 'python_version >= 3.8 (matches most systems)', line: "six==1.16.0 ; python_version >= '3.8'", pkg: 'six', via: 'marker-test'},
			{desc: 'os_name == posix (matches linux/macOS)', line: "six==1.16.0 ; os_name == 'posix'", pkg: 'six', via: 'marker-test'},
		]

		INCLUDED_MARKERS.forEach(({desc, line, pkg, via}) => {
			test(`packages with matching marker included in stack: ${desc}`, injectAndRun(
				makeUvExport([{line, via}]),
				async () => {
					let result = await uvProvider.provideStack(path.join(fixtureDir, 'pyproject.toml'))
					let sbom = JSON.parse(result.content)
					let names = sbom.components.map(c => c.name)
					expect(names).to.include(pkg,
						`${pkg} with marker "${desc}" should be included on this platform`)
				}
			)).timeout(TIMEOUT)
		})

		test('click dependency tree should not reference colorama when marker does not match', injectAndRun(
			makeUvExport([{line: "colorama==0.4.6 ; sys_platform == 'win32'"}]),
			async () => {
				let result = await uvProvider.provideStack(path.join(fixtureDir, 'pyproject.toml'))
				let sbom = JSON.parse(result.content)
				let clickDep = sbom.dependencies.find(d => d.ref.includes('/click@'))
				expect(clickDep).to.exist
				expect(clickDep.dependsOn).to.deep.equal([],
					'click should have no children since colorama is marker-filtered')
			}
		)).timeout(TIMEOUT)
	})

	suite('poetry projects - PEP 508 marker filtering (TC-4042 reproducer)', () => {
		const fixtureDir = `${MANIFESTS}/poetry_marker_filtering`

		function injectPoetryAndRun(treeLines, allLines, fn) {
			return async () => {
				process.env['TRUSTIFY_DA_POETRY_SHOW_TREE'] = Buffer.from(treeLines.join('\n')).toString('base64')
				process.env['TRUSTIFY_DA_POETRY_SHOW_ALL'] = Buffer.from(allLines.join('\n')).toString('base64')
				try { await fn() } finally {
					delete process.env['TRUSTIFY_DA_POETRY_SHOW_TREE']
					delete process.env['TRUSTIFY_DA_POETRY_SHOW_ALL']
				}
			}
		}

		const showAll = [
			'click            8.3.1  Composable command line interface toolkit',
			'colorama         0.4.6  Cross-platform colored terminal text.',
			'six              1.16.0 Python 2 and 3 compatibility utilities',
			'win32-setctime   1.1.0  A small Python utility to set file creation time on Windows',
			'pyreadline3      3.4.1  A Python implementation of GNU readline.',
		]

		const EXCLUDED_CASES = [
			{
				desc: 'platform_system == Windows (colorama via click)',
				tree: [
					'click 8.3.1 Composable command line interface toolkit',
					'└── colorama *',
					'six 1.16.0 Python 2 and 3 compatibility utilities',
				],
				excluded: 'colorama',
				included: ['click', 'six'],
			},
			{
				desc: 'os_name == nt (win32-setctime as direct dep)',
				tree: [
					'click 8.3.1 Composable command line interface toolkit',
					'six 1.16.0 Python 2 and 3 compatibility utilities',
					'win32-setctime 1.1.0 A small Python utility to set file creation time on Windows',
				],
				excluded: 'win32-setctime',
				included: ['click', 'six'],
			},
			{
				desc: 'sys_platform == win32 (pyreadline3 as direct dep)',
				tree: [
					'click 8.3.1 Composable command line interface toolkit',
					'six 1.16.0 Python 2 and 3 compatibility utilities',
					'pyreadline3 3.4.1 A Python implementation of GNU readline.',
				],
				excluded: 'pyreadline3',
				included: ['click', 'six'],
			},
		]

		EXCLUDED_CASES.forEach(({desc, tree, excluded, included}) => {
			test(`packages with non-matching marker excluded from stack: ${desc}`, injectPoetryAndRun(
				tree, showAll,
				async () => {
					let result = await poetryProvider.provideStack(path.join(fixtureDir, 'pyproject.toml'))
					let sbom = JSON.parse(result.content)
					let names = sbom.components.map(c => c.name)
					for (let inc of included) {
						expect(names).to.include(inc)
					}
					expect(names).to.not.include(excluded,
						`${excluded} with marker "${desc}" should be excluded on this platform`)
				}
			)).timeout(TIMEOUT)
		})

		test('click dependency tree should not reference colorama when marker does not match', injectPoetryAndRun(
			[
				'click 8.3.1 Composable command line interface toolkit',
				'└── colorama *',
				'six 1.16.0 Python 2 and 3 compatibility utilities',
			],
			showAll,
			async () => {
				let result = await poetryProvider.provideStack(path.join(fixtureDir, 'pyproject.toml'))
				let sbom = JSON.parse(result.content)
				let clickDep = sbom.dependencies.find(d => d.ref.includes('/click@'))
				expect(clickDep).to.exist
				expect(clickDep.dependsOn).to.deep.equal([],
					'click should have no children since colorama is marker-filtered')
			}
		)).timeout(TIMEOUT)
	})

	suite('workspace/monorepo support', () => {
		const uvWorkspace = `${MANIFESTS}/uv_workspace`

		/** Verifies uv walks up to parent directory to find uv.lock. */
		test('uv validateLockFile finds uv.lock in parent directory', () => {
			expect(uvProvider.validateLockFile(
				path.join(uvWorkspace, 'packages/sub-pkg')
			)).to.equal(true)
		})

		/** Verifies poetry does not walk up directories since it has no native workspace support. */
		test('poetry validateLockFile does not walk up to parent directory', () => {
			// Poetry has no native workspace support (python-poetry/poetry#2270).
			// Each poetry project is treated independently — no lock file walk-up.
			let tmpDir = `${MANIFESTS}/boundary_test_poetry`
			let subDir = path.join(tmpDir, 'packages', 'child')
			fs.mkdirSync(subDir, { recursive: true })
			fs.writeFileSync(path.join(tmpDir, 'pyproject.toml'),
				'[tool.poetry]\nname = "root"\nversion = "0.1.0"\n')
			fs.writeFileSync(path.join(tmpDir, 'poetry.lock'), '')
			fs.writeFileSync(path.join(subDir, 'pyproject.toml'),
				'[tool.poetry]\nname = "child"\nversion = "0.1.0"\n')
			try {
				expect(poetryProvider.validateLockFile(subDir)).to.equal(false)
			} finally {
				fs.rmSync(tmpDir, { recursive: true, force: true })
			}
		})

		/** Verifies lock file search stops at uv workspace root when uv.lock is absent. */
		test('validateLockFile stops at uv workspace root boundary when lock file is absent', () => {
			let tmpDir = `${MANIFESTS}/boundary_test`
			let subDir = path.join(tmpDir, 'packages', 'child')
			fs.mkdirSync(subDir, { recursive: true })
			fs.writeFileSync(path.join(tmpDir, 'pyproject.toml'),
				'[tool.uv.workspace]\nmembers = ["packages/*"]\n')
			fs.writeFileSync(path.join(subDir, 'pyproject.toml'),
				'[project]\nname = "child"\nversion = "0.1.0"\n')
			try {
				expect(uvProvider.validateLockFile(subDir)).to.equal(false)
			} finally {
				fs.rmSync(tmpDir, { recursive: true, force: true })
			}
		})

		/** Verifies TRUSTIFY_DA_WORKSPACE_DIR override redirects lock file search. */
		test('TRUSTIFY_DA_WORKSPACE_DIR override directs lock file search', () => {
			let overrideDir = path.resolve(uvWorkspace)
			expect(uvProvider.validateLockFile(
				`${MANIFESTS}/poetry_lock`,
				{ TRUSTIFY_DA_WORKSPACE_DIR: overrideDir }
			)).to.equal(true)

			expect(uvProvider.validateLockFile(
				`${MANIFESTS}/poetry_lock`,
				{ TRUSTIFY_DA_WORKSPACE_DIR: '/nonexistent/dir' }
			)).to.equal(false)
		});

		/** Verifies SBOM output for each workspace package (root, mid-pkg, sub-pkg). */
		[
			{manifestPath: '', label: 'root'},
			{manifestPath: 'packages/mid-pkg', label: 'mid-package'},
			{manifestPath: 'packages/sub-pkg', label: 'sub-package'},
		].forEach(({manifestPath, label}) => {
			const pkgDir = manifestPath ? path.join(uvWorkspace, manifestPath) : uvWorkspace

			SBOM_CASES.forEach(({type, method, fixture}) => {
				test(`verify uv workspace ${label} ${type} analysis`, async () => {
					let expectedSbom = fs.readFileSync(path.join(pkgDir, fixture)).toString().trim()
					expectedSbom = JSON.stringify(JSON.parse(expectedSbom))
					let result = await uvProvider[method](path.join(pkgDir, 'pyproject.toml'))
					expect(result).to.deep.equal({
						ecosystem: 'pip',
						contentType: 'application/vnd.cyclonedx+json',
						content: expectedSbom
					})
				}).timeout(TIMEOUT)
			})
		})
	})

}).beforeAll(() => {
	originalPlatform = process.platform
	Object.defineProperty(process, 'platform', { value: 'linux', configurable: true })
	clock = useFakeTimers(new Date('2023-10-01T00:00:00.000Z'))
}).afterAll(() => {
	Object.defineProperty(process, 'platform', { value: originalPlatform, configurable: true })
	clock.restore()
})
