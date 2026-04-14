import fs from 'fs'

import { expect } from 'chai'
import { useFakeTimers } from 'sinon'

import Python_poetry from '../../src/providers/python_poetry.js'
import Python_uv from '../../src/providers/python_uv.js'

let clock

const TIMEOUT = process.env.GITHUB_ACTIONS ? 30000 : 10000

const uvProvider = new Python_uv()
const poetryProvider = new Python_poetry()

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

}).beforeAll(() => clock = useFakeTimers(new Date('2023-10-01T00:00:00.000Z'))).afterAll(() => clock.restore())
