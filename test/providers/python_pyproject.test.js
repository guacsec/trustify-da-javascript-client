import fs from 'fs'
import path from 'path'

import { expect } from 'chai'
import { useFakeTimers } from 'sinon'

import Python_pip_pyproject from '../../src/providers/python_pip_pyproject.js'
import Python_poetry from '../../src/providers/python_poetry.js'
import Python_uv from '../../src/providers/python_uv.js'

let clock

const TIMEOUT = process.env.GITHUB_ACTIONS ? 30000 : 10000

const uvProvider = new Python_uv()
const poetryProvider = new Python_poetry()
const pipProvider = new Python_pip_pyproject()

suite('testing the python-pyproject data provider', () => {
	[
		{name: 'pyproject.toml', expected: true},
		{name: 'requirements.txt', expected: false},
		{name: 'Cargo.toml', expected: false},
	].forEach(testCase => {
		test(`verify isSupported returns ${testCase.expected} for ${testCase.name}`, () =>
			expect(uvProvider.isSupported(testCase.name)).to.equal(testCase.expected)
		)
	})

	test('verify uv validateLockFile returns true when uv.lock exists', () => {
		expect(uvProvider.validateLockFile('test/providers/tst_manifests/pyproject/uv_lock')).to.equal(true)
	})

	test('verify uv validateLockFile returns false when uv.lock is missing', () => {
		expect(uvProvider.validateLockFile('test/providers/tst_manifests/pyproject/poetry_lock')).to.equal(false)
	})

	test('verify poetry validateLockFile returns true when poetry.lock exists', () => {
		expect(poetryProvider.validateLockFile('test/providers/tst_manifests/pyproject/poetry_lock')).to.equal(true)
	})

	test('verify poetry validateLockFile returns false when poetry.lock is missing', () => {
		expect(poetryProvider.validateLockFile('test/providers/tst_manifests/pyproject/uv_lock')).to.equal(false)
	})

	suite('uv projects (via uv export)', () => {
		test('verify pyproject.toml sbom provided for stack analysis with uv', async () => {
			let expectedSbom = fs.readFileSync('test/providers/tst_manifests/pyproject/pep621_ignore_and_extras/expected_stack_sbom.json').toString()
			expectedSbom = JSON.stringify(JSON.parse(expectedSbom))
			let result = await uvProvider.provideStack('test/providers/tst_manifests/pyproject/pep621_ignore_and_extras/pyproject.toml')
			expect(result).to.deep.equal({
				ecosystem: 'pip',
				contentType: 'application/vnd.cyclonedx+json',
				content: expectedSbom
			})
		}).timeout(TIMEOUT)

		test('verify pyproject.toml sbom provided for component analysis with uv', async () => {
			let expectedSbom = fs.readFileSync('test/providers/tst_manifests/pyproject/pep621_ignore_and_extras/expected_component_sbom.json').toString().trim()
			expectedSbom = JSON.stringify(JSON.parse(expectedSbom))
			let result = await uvProvider.provideComponent('test/providers/tst_manifests/pyproject/pep621_ignore_and_extras/pyproject.toml')
			expect(result).to.deep.equal({
				ecosystem: 'pip',
				contentType: 'application/vnd.cyclonedx+json',
				content: expectedSbom
			})
		}).timeout(TIMEOUT)

		test('exhortignore and trustify-da-ignore exclude deps from component analysis', async () => {
			let result = await uvProvider.provideComponent('test/providers/tst_manifests/pyproject/pep621_ignore_and_extras/pyproject.toml')
			let sbom = JSON.parse(result.content)
			let names = sbom.components.map(c => c.name)
			expect(names).to.not.include('uvicorn')
			expect(names).to.not.include('markupsafe')
			expect(names).to.include('flask')
			expect(names).to.include('requests')
		}).timeout(TIMEOUT)

		test('ignored transitive dep excluded from stack analysis tree', async () => {
			let result = await uvProvider.provideStack('test/providers/tst_manifests/pyproject/pep621_ignore_and_extras/pyproject.toml')
			let sbom = JSON.parse(result.content)
			let names = sbom.components.map(c => c.name)
			expect(names).to.not.include('uvicorn')
			expect(names).to.not.include('markupsafe')
			let jinja2Dep = sbom.dependencies.find(d => d.ref.includes('/jinja2@'))
			expect(jinja2Dep).to.exist
			expect(jinja2Dep.dependsOn).to.deep.equal([])
		}).timeout(TIMEOUT)

		test('name canonicalization: typing_extensions matches typing-extensions', async () => {
			let result = await uvProvider.provideComponent('test/providers/tst_manifests/pyproject/pep621_ignore_and_extras/pyproject.toml')
			let sbom = JSON.parse(result.content)
			let typingExt = sbom.components.find(c => c.name === 'typing-extensions')
			expect(typingExt).to.exist
			expect(typingExt.version).to.equal('4.1.1')
		}).timeout(TIMEOUT)
	})

	suite('uv projects - uv_lock manifest', () => {
		test('verify pyproject.toml sbom provided for stack analysis with uv_lock', async () => {
			let expectedSbom = fs.readFileSync('test/providers/tst_manifests/pyproject/uv_lock/expected_stack_sbom.json').toString()
			expectedSbom = JSON.stringify(JSON.parse(expectedSbom))
			let result = await uvProvider.provideStack('test/providers/tst_manifests/pyproject/uv_lock/pyproject.toml')
			expect(result).to.deep.equal({
				ecosystem: 'pip',
				contentType: 'application/vnd.cyclonedx+json',
				content: expectedSbom
			})
		}).timeout(TIMEOUT)

		test('verify pyproject.toml sbom provided for component analysis with uv_lock', async () => {
			let expectedSbom = fs.readFileSync('test/providers/tst_manifests/pyproject/uv_lock/expected_component_sbom.json').toString().trim()
			expectedSbom = JSON.stringify(JSON.parse(expectedSbom))
			let result = await uvProvider.provideComponent('test/providers/tst_manifests/pyproject/uv_lock/pyproject.toml')
			expect(result).to.deep.equal({
				ecosystem: 'pip',
				contentType: 'application/vnd.cyclonedx+json',
				content: expectedSbom
			})
		}).timeout(TIMEOUT)
	})

	suite('poetry projects (via poetry show)', () => {
		test('verify pyproject.toml sbom provided for stack analysis with poetry', async () => {
			let expectedSbom = fs.readFileSync('test/providers/tst_manifests/pyproject/poetry_lock/expected_stack_sbom.json').toString()
			expectedSbom = JSON.stringify(JSON.parse(expectedSbom))
			let result = await poetryProvider.provideStack('test/providers/tst_manifests/pyproject/poetry_lock/pyproject.toml')
			expect(result).to.deep.equal({
				ecosystem: 'pip',
				contentType: 'application/vnd.cyclonedx+json',
				content: expectedSbom
			})
		}).timeout(TIMEOUT)

		test('verify pyproject.toml sbom provided for component analysis with poetry', async () => {
			let expectedSbom = fs.readFileSync('test/providers/tst_manifests/pyproject/poetry_lock/expected_component_sbom.json').toString().trim()
			expectedSbom = JSON.stringify(JSON.parse(expectedSbom))
			let result = await poetryProvider.provideComponent('test/providers/tst_manifests/pyproject/poetry_lock/pyproject.toml')
			expect(result).to.deep.equal({
				ecosystem: 'pip',
				contentType: 'application/vnd.cyclonedx+json',
				content: expectedSbom
			})
		}).timeout(TIMEOUT)

		test('resolved versions come from poetry show --all, not constraints', async () => {
			let result = await poetryProvider.provideStack('test/providers/tst_manifests/pyproject/poetry_lock/pyproject.toml')
			let sbom = JSON.parse(result.content)
			let markupsafe = sbom.components.find(c => c.name === 'markupsafe')
			expect(markupsafe.version).to.equal('3.0.3')
			let urllib3 = sbom.components.find(c => c.name === 'urllib3')
			expect(urllib3.version).to.equal('2.6.3')
		}).timeout(TIMEOUT)

		test('exhortignore filtering excludes click and its exclusive transitive deps', async () => {
			let result = await poetryProvider.provideStack('test/providers/tst_manifests/pyproject/poetry_lock/pyproject.toml')
			let sbom = JSON.parse(result.content)
			let names = sbom.components.map(c => c.name)
			expect(names).to.not.include('click')
			expect(names).to.include('flask')
			expect(names).to.include('requests')
		}).timeout(TIMEOUT)
	})

	suite('poetry projects - poetry_only_deps manifest', () => {
		test('verify pyproject.toml sbom provided for stack analysis with poetry_only_deps', async () => {
			let expectedSbom = fs.readFileSync('test/providers/tst_manifests/pyproject/poetry_only_deps/expected_stack_sbom.json').toString()
			expectedSbom = JSON.stringify(JSON.parse(expectedSbom))
			let result = await poetryProvider.provideStack('test/providers/tst_manifests/pyproject/poetry_only_deps/pyproject.toml')
			expect(result).to.deep.equal({
				ecosystem: 'pip',
				contentType: 'application/vnd.cyclonedx+json',
				content: expectedSbom
			})
		}).timeout(TIMEOUT)

		test('verify pyproject.toml sbom provided for component analysis with poetry_only_deps', async () => {
			let expectedSbom = fs.readFileSync('test/providers/tst_manifests/pyproject/poetry_only_deps/expected_component_sbom.json').toString().trim()
			expectedSbom = JSON.stringify(JSON.parse(expectedSbom))
			let result = await poetryProvider.provideComponent('test/providers/tst_manifests/pyproject/poetry_only_deps/pyproject.toml')
			expect(result).to.deep.equal({
				ecosystem: 'pip',
				contentType: 'application/vnd.cyclonedx+json',
				content: expectedSbom
			})
		}).timeout(TIMEOUT)
	})

	/** Verifies the pip provider's validateLockFile always returns true (fallback). */
	test('verify pip validateLockFile always returns true (fallback provider)', () => {
		expect(pipProvider.validateLockFile('test/providers/tst_manifests/pyproject/pip_pep621')).to.equal(true)
		expect(pipProvider.validateLockFile('/nonexistent/dir')).to.equal(true)
	})

	suite('pip projects (via pip --dry-run --report)', () => {
		const pipFixtureDir = 'test/providers/tst_manifests/pyproject/pip_pep621'
		const pipIgnoreDir = 'test/providers/tst_manifests/pyproject/pip_pep621_ignore'
		let savedEnv

		setup(() => {
			savedEnv = process.env.TRUSTIFY_DA_PIP_REPORT
			let report = fs.readFileSync(path.join(pipFixtureDir, 'pip_report.json'), 'utf-8')
			process.env.TRUSTIFY_DA_PIP_REPORT = Buffer.from(report).toString('base64')
		})

		teardown(() => {
			if (savedEnv === undefined) {
				delete process.env.TRUSTIFY_DA_PIP_REPORT
			} else {
				process.env.TRUSTIFY_DA_PIP_REPORT = savedEnv
			}
		})

		/** Verifies stack analysis produces correct SBOM with transitive deps. */
		test('verify pyproject.toml sbom provided for stack analysis with pip', async () => {
			// Given a PEP 621 pyproject.toml and pre-recorded pip report
			let expectedSbom = fs.readFileSync(path.join(pipFixtureDir, 'expected_stack_sbom.json')).toString()
			expectedSbom = JSON.stringify(JSON.parse(expectedSbom))

			// When running stack analysis
			let result = await pipProvider.provideStack(path.join(pipFixtureDir, 'pyproject.toml'))

			// Then the SBOM matches expected output
			expect(result).to.deep.equal({
				ecosystem: 'pip',
				contentType: 'application/vnd.cyclonedx+json',
				content: expectedSbom
			})
		}).timeout(TIMEOUT)

		/** Verifies component analysis produces correct SBOM with direct deps only. */
		test('verify pyproject.toml sbom provided for component analysis with pip', async () => {
			// Given a PEP 621 pyproject.toml and pre-recorded pip report
			let expectedSbom = fs.readFileSync(path.join(pipFixtureDir, 'expected_component_sbom.json')).toString().trim()
			expectedSbom = JSON.stringify(JSON.parse(expectedSbom))

			// When running component analysis
			let result = await pipProvider.provideComponent(path.join(pipFixtureDir, 'pyproject.toml'))

			// Then the SBOM matches expected output
			expect(result).to.deep.equal({
				ecosystem: 'pip',
				contentType: 'application/vnd.cyclonedx+json',
				content: expectedSbom
			})
		}).timeout(TIMEOUT)

		/** Verifies direct and transitive deps are correctly classified in stack SBOM. */
		test('stack analysis classifies direct and transitive dependencies correctly', async () => {
			// When running stack analysis
			let result = await pipProvider.provideStack(path.join(pipFixtureDir, 'pyproject.toml'))
			let sbom = JSON.parse(result.content)

			// Then requests is a direct dep of the root
			let rootDep = sbom.dependencies.find(d => d.ref.includes('/test-project@'))
			expect(rootDep.dependsOn).to.have.lengthOf(1)
			expect(rootDep.dependsOn[0]).to.include('/requests@')

			// And requests has its own transitive deps
			let requestsDep = sbom.dependencies.find(d => d.ref.includes('/requests@'))
			let transNames = requestsDep.dependsOn.map(d => d.split('/').pop().split('@')[0])
			expect(transNames).to.include('certifi')
			expect(transNames).to.include('charset-normalizer')
			expect(transNames).to.include('idna')
			expect(transNames).to.include('urllib3')
		}).timeout(TIMEOUT)

		/** Verifies extras-only dependencies (e.g. PySocks for socks extra) are excluded. */
		test('extras-only dependencies are filtered from the dependency tree', async () => {
			let result = await pipProvider.provideStack(path.join(pipFixtureDir, 'pyproject.toml'))
			let sbom = JSON.parse(result.content)
			let names = sbom.components.map(c => c.name)
			expect(names).to.not.include('PySocks')
			expect(names).to.not.include('pysocks')
		}).timeout(TIMEOUT)

		/** Verifies exhortignore marker in PEP 621 dependencies excludes the dep. */
		test('exhortignore marker excludes dep from component analysis', async () => {
			// Given a pyproject.toml with requests marked as exhortignore
			let result = await pipProvider.provideComponent(path.join(pipIgnoreDir, 'pyproject.toml'))
			let sbom = JSON.parse(result.content)

			// Then requests is excluded
			let names = sbom.components.map(c => c.name)
			expect(names).to.not.include('requests')
		}).timeout(TIMEOUT)

		/** Verifies exhortignore excludes dep and its exclusive transitive deps from stack analysis. */
		test('exhortignore marker excludes dep from stack analysis', async () => {
			// Given a pyproject.toml with requests marked as exhortignore
			let result = await pipProvider.provideStack(path.join(pipIgnoreDir, 'pyproject.toml'))
			let sbom = JSON.parse(result.content)

			// Then requests and all its exclusive transitive deps are excluded
			let names = sbom.components.map(c => c.name)
			expect(names).to.not.include('requests')
		}).timeout(TIMEOUT)

		/** Verifies name canonicalization (charset_normalizer → charset-normalizer). */
		test('name canonicalization: charset_normalizer resolved as charset-normalizer', async () => {
			let result = await pipProvider.provideStack(path.join(pipFixtureDir, 'pyproject.toml'))
			let sbom = JSON.parse(result.content)
			let pkg = sbom.components.find(c => c.name === 'charset-normalizer')
			expect(pkg).to.exist
			expect(pkg.version).to.equal('3.4.7')
		}).timeout(TIMEOUT)
	})

	test('validateLockFile returns false when no lock file is present', () => {
		let tmpDir = 'test/providers/tst_manifests/pyproject/no_lock_file_dummy'
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

	suite('workspace/monorepo support', () => {
		const uvWorkspace = 'test/providers/tst_manifests/pyproject/uv_workspace'

		test('uv validateLockFile finds uv.lock in parent directory', () => {
			expect(uvProvider.validateLockFile(
				path.join(uvWorkspace, 'packages/sub-pkg')
			)).to.equal(true)
		})

		test('poetry validateLockFile does not walk up to parent directory', () => {
			// Poetry has no native workspace support (python-poetry/poetry#2270).
			// Each poetry project is treated independently — no lock file walk-up.
			let tmpDir = 'test/providers/tst_manifests/pyproject/boundary_test_poetry'
			let subDir = path.join(tmpDir, 'packages', 'child')
			fs.mkdirSync(subDir, { recursive: true })
			fs.writeFileSync(path.join(tmpDir, 'pyproject.toml'),
				'[tool.poetry]\nname = "root"\nversion = "0.1.0"\n')
			fs.writeFileSync(path.join(tmpDir, 'poetry.lock'), '')
			fs.writeFileSync(path.join(subDir, 'pyproject.toml'),
				'[tool.poetry]\nname = "child"\nversion = "0.1.0"\n')
			try {
				// poetry.lock exists at root but poetry should NOT walk up
				expect(poetryProvider.validateLockFile(subDir)).to.equal(false)
			} finally {
				fs.rmSync(tmpDir, { recursive: true, force: true })
			}
		})

		test('validateLockFile stops at uv workspace root boundary when lock file is absent', () => {
			let tmpDir = 'test/providers/tst_manifests/pyproject/boundary_test'
			let subDir = path.join(tmpDir, 'packages', 'child')
			fs.mkdirSync(subDir, { recursive: true })
			// root has workspace marker but no lock file
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

		test('TRUSTIFY_DA_WORKSPACE_DIR override directs lock file search', () => {
			let overrideDir = path.resolve(uvWorkspace)
			expect(uvProvider.validateLockFile(
				'test/providers/tst_manifests/pyproject/poetry_lock',
				{ TRUSTIFY_DA_WORKSPACE_DIR: overrideDir }
			)).to.equal(true)

			expect(uvProvider.validateLockFile(
				'test/providers/tst_manifests/pyproject/poetry_lock',
				{ TRUSTIFY_DA_WORKSPACE_DIR: '/nonexistent/dir' }
			)).to.equal(false)
		})

		test('verify uv workspace root stack analysis', async () => {
			let expectedSbom = fs.readFileSync(path.join(uvWorkspace, 'expected_stack_sbom.json')).toString()
			expectedSbom = JSON.stringify(JSON.parse(expectedSbom))
			let result = await uvProvider.provideStack(path.join(uvWorkspace, 'pyproject.toml'))
			expect(result).to.deep.equal({
				ecosystem: 'pip',
				contentType: 'application/vnd.cyclonedx+json',
				content: expectedSbom
			})
		}).timeout(TIMEOUT)

		test('verify uv workspace root component analysis', async () => {
			let expectedSbom = fs.readFileSync(path.join(uvWorkspace, 'expected_component_sbom.json')).toString().trim()
			expectedSbom = JSON.stringify(JSON.parse(expectedSbom))
			let result = await uvProvider.provideComponent(path.join(uvWorkspace, 'pyproject.toml'))
			expect(result).to.deep.equal({
				ecosystem: 'pip',
				contentType: 'application/vnd.cyclonedx+json',
				content: expectedSbom
			})
		}).timeout(TIMEOUT)

		test('verify uv workspace mid-package stack analysis', async () => {
			let expectedSbom = fs.readFileSync(path.join(uvWorkspace, 'packages/mid-pkg/expected_stack_sbom.json')).toString()
			expectedSbom = JSON.stringify(JSON.parse(expectedSbom))
			let result = await uvProvider.provideStack(path.join(uvWorkspace, 'packages/mid-pkg/pyproject.toml'))
			expect(result).to.deep.equal({
				ecosystem: 'pip',
				contentType: 'application/vnd.cyclonedx+json',
				content: expectedSbom
			})
		}).timeout(TIMEOUT)

		test('verify uv workspace mid-package component analysis', async () => {
			let expectedSbom = fs.readFileSync(path.join(uvWorkspace, 'packages/mid-pkg/expected_component_sbom.json')).toString().trim()
			expectedSbom = JSON.stringify(JSON.parse(expectedSbom))
			let result = await uvProvider.provideComponent(path.join(uvWorkspace, 'packages/mid-pkg/pyproject.toml'))
			expect(result).to.deep.equal({
				ecosystem: 'pip',
				contentType: 'application/vnd.cyclonedx+json',
				content: expectedSbom
			})
		}).timeout(TIMEOUT)

		test('verify uv workspace sub-package stack analysis', async () => {
			let expectedSbom = fs.readFileSync(path.join(uvWorkspace, 'packages/sub-pkg/expected_stack_sbom.json')).toString()
			expectedSbom = JSON.stringify(JSON.parse(expectedSbom))
			let result = await uvProvider.provideStack(path.join(uvWorkspace, 'packages/sub-pkg/pyproject.toml'))
			expect(result).to.deep.equal({
				ecosystem: 'pip',
				contentType: 'application/vnd.cyclonedx+json',
				content: expectedSbom
			})
		}).timeout(TIMEOUT)

		test('verify uv workspace sub-package component analysis', async () => {
			let expectedSbom = fs.readFileSync(path.join(uvWorkspace, 'packages/sub-pkg/expected_component_sbom.json')).toString().trim()
			expectedSbom = JSON.stringify(JSON.parse(expectedSbom))
			let result = await uvProvider.provideComponent(path.join(uvWorkspace, 'packages/sub-pkg/pyproject.toml'))
			expect(result).to.deep.equal({
				ecosystem: 'pip',
				contentType: 'application/vnd.cyclonedx+json',
				content: expectedSbom
			})
		}).timeout(TIMEOUT)
	})

}).beforeAll(() => clock = useFakeTimers(new Date('2023-10-01T00:00:00.000Z'))).afterAll(() => clock.restore())
