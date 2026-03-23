import fs from 'node:fs'
import path from 'node:path'

import { expect } from 'chai'
import esmock from 'esmock'
import { http, HttpResponse } from 'msw'
import { setupServer } from 'msw/node'

const BACKEND_URL = 'http://localhost:9999'
const BACKEND_OPTS = { TRUSTIFY_DA_BACKEND_URL: BACKEND_URL }

/**
 * Helper: create a temporary monorepo workspace on disk.
 * Returns the root path and a cleanup function.
 */
function createTmpWorkspace(name, { packages = [], pnpmWorkspace = null, rootPkg = null, lockFile = 'package-lock.json' } = {}) {
	const tmpDir = path.resolve(`test/tst_manifests_batch_${name}`)
	fs.mkdirSync(tmpDir, { recursive: true })

	if (rootPkg) {
		fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify(rootPkg))
	}
	if (pnpmWorkspace) {
		fs.writeFileSync(path.join(tmpDir, 'pnpm-workspace.yaml'), pnpmWorkspace)
	}
	if (lockFile) {
		fs.writeFileSync(path.join(tmpDir, lockFile), '{}')
	}

	for (const pkg of packages) {
		const pkgDir = path.join(tmpDir, pkg.dir)
		fs.mkdirSync(pkgDir, { recursive: true })
		fs.writeFileSync(path.join(pkgDir, 'package.json'), JSON.stringify(pkg.content))
	}

	return { root: tmpDir, cleanup: () => fs.rmSync(tmpDir, { recursive: true, force: true }) }
}

/**
 * Build a mock provider module that returns a deterministic SBOM for each manifest.
 */
function buildMockProviders(sbomMap) {
	const mockProvider = {
		isSupported: () => true,
		validateLockFile: () => true,
		provideStack: (manifestPath) => {
			const sbom = sbomMap[manifestPath]
			if (!sbom) {
				throw new Error(`No mock SBOM for ${manifestPath}`)
			}
			return {
				ecosystem: 'npm',
				content: JSON.stringify(sbom),
				contentType: 'application/vnd.cyclonedx+json',
			}
		},
	}
	return {
		availableProviders: [mockProvider],
		match: () => mockProvider,
	}
}

function makeSbom(name, version) {
	return {
		metadata: {
			component: {
				purl: `pkg:npm/${name}@${version}`,
				'bom-ref': `pkg:npm/${name}@${version}`,
			},
		},
		components: [],
	}
}

suite('stackAnalysisBatch', () => {
	let server
	let capturedBody

	suiteSetup(() => {
		server = setupServer(
			http.post(`${BACKEND_URL}/api/v5/batch-analysis`, async ({ request }) => {
				capturedBody = await request.json()
				const report = {}
				for (const purl of Object.keys(capturedBody)) {
					report[purl] = { providers: {} }
				}
				return HttpResponse.json(report)
			})
		)
		server.listen()
	})

	suiteTeardown(() => {
		server.close()
	})

	setup(() => {
		capturedBody = null
	})

	test('discovers JS workspace packages, generates SBOMs, and sends batch request', async () => {
		const { root, cleanup } = createTmpWorkspace('js_batch', {
			rootPkg: { name: 'root', version: '1.0.0', workspaces: ['packages/*'] },
			packages: [
				{ dir: 'packages/app-a', content: { name: 'app-a', version: '1.0.0' } },
				{ dir: 'packages/app-b', content: { name: 'app-b', version: '2.0.0' } },
			],
		})

		try {
			const appASbom = makeSbom('app-a', '1.0.0')
			const appBSbom = makeSbom('app-b', '2.0.0')
			const rootSbom = makeSbom('root', '1.0.0')

			const sbomMap = {}
			sbomMap[path.join(root, 'package.json')] = rootSbom
			sbomMap[path.join(root, 'packages/app-a/package.json')] = appASbom
			sbomMap[path.join(root, 'packages/app-b/package.json')] = appBSbom

			const mockProviders = buildMockProviders(sbomMap)
			const client = await esmock('../src/index.js', {
				'../src/provider.js': mockProviders,
			})

			const result = await client.stackAnalysisBatch(root, false, BACKEND_OPTS)

			expect(result).to.be.an('object')
			expect(capturedBody).to.be.an('object')
			const purls = Object.keys(capturedBody)
			expect(purls).to.include('pkg:npm/app-a@1.0.0')
			expect(purls).to.include('pkg:npm/app-b@2.0.0')
			expect(purls).to.include('pkg:npm/root@1.0.0')
		} finally {
			cleanup()
		}
	})

	test('returns metadata when batchMetadata option is set', async () => {
		const { root, cleanup } = createTmpWorkspace('js_meta', {
			rootPkg: { name: 'meta-root', version: '1.0.0', workspaces: ['packages/*'] },
			packages: [
				{ dir: 'packages/pkg-a', content: { name: 'pkg-a', version: '1.0.0' } },
			],
		})

		try {
			const sbomMap = {}
			sbomMap[path.join(root, 'package.json')] = makeSbom('meta-root', '1.0.0')
			sbomMap[path.join(root, 'packages/pkg-a/package.json')] = makeSbom('pkg-a', '1.0.0')

			const mockProviders = buildMockProviders(sbomMap)
			const client = await esmock('../src/index.js', {
				'../src/provider.js': mockProviders,
			})

			const result = await client.stackAnalysisBatch(root, false, {
				...BACKEND_OPTS,
				batchMetadata: true,
			})

			expect(result).to.have.property('analysis')
			expect(result).to.have.property('metadata')
			expect(result.metadata.ecosystem).to.equal('javascript')
			expect(result.metadata.successful).to.equal(2)
			expect(result.metadata.failed).to.equal(0)
		} finally {
			cleanup()
		}
	})

	test('skips invalid package.json and continues in default mode', async () => {
		const { root, cleanup } = createTmpWorkspace('js_invalid', {
			rootPkg: { name: 'root-inv', version: '1.0.0', workspaces: ['packages/*'] },
			packages: [
				{ dir: 'packages/good', content: { name: 'good', version: '1.0.0' } },
				{ dir: 'packages/bad', content: { version: '1.0.0' } }, // missing name
			],
		})

		try {
			const sbomMap = {}
			sbomMap[path.join(root, 'package.json')] = makeSbom('root-inv', '1.0.0')
			sbomMap[path.join(root, 'packages/good/package.json')] = makeSbom('good', '1.0.0')

			const mockProviders = buildMockProviders(sbomMap)
			const client = await esmock('../src/index.js', {
				'../src/provider.js': mockProviders,
			})

			const result = await client.stackAnalysisBatch(root, false, {
				...BACKEND_OPTS,
				batchMetadata: true,
			})

			expect(result.metadata.failed).to.be.at.least(1)
			expect(result.metadata.errors.some(e => e.phase === 'validation')).to.be.true
			expect(capturedBody).to.be.an('object')
			expect(Object.keys(capturedBody)).to.include('pkg:npm/good@1.0.0')
		} finally {
			cleanup()
		}
	})

	test('throws on first invalid package.json in fail-fast mode', async () => {
		const { root, cleanup } = createTmpWorkspace('js_failfast', {
			rootPkg: { name: 'root-ff', version: '1.0.0', workspaces: ['packages/*'] },
			packages: [
				{ dir: 'packages/bad', content: { version: '1.0.0' } }, // missing name
				{ dir: 'packages/good', content: { name: 'good', version: '1.0.0' } },
			],
		})

		try {
			const sbomMap = {}
			sbomMap[path.join(root, 'package.json')] = makeSbom('root-ff', '1.0.0')
			sbomMap[path.join(root, 'packages/good/package.json')] = makeSbom('good', '1.0.0')

			const mockProviders = buildMockProviders(sbomMap)
			const client = await esmock('../src/index.js', {
				'../src/provider.js': mockProviders,
			})

			try {
				await client.stackAnalysisBatch(root, false, {
					...BACKEND_OPTS,
					continueOnError: false,
					batchMetadata: true,
				})
				expect.fail('should have thrown')
			} catch (err) {
				expect(err.message).to.match(/Invalid package\.json/i)
				expect(err.batchMetadata).to.be.an('object')
			}
		} finally {
			cleanup()
		}
	})

	test('throws when no workspace manifests found', async () => {
		const tmpDir = path.resolve('test/tst_manifests_batch_empty')
		fs.mkdirSync(tmpDir, { recursive: true })

		try {
			const client = await esmock('../src/index.js', {
				'../src/provider.js': buildMockProviders({}),
			})

			try {
				await client.stackAnalysisBatch(tmpDir, false, BACKEND_OPTS)
				expect.fail('should have thrown')
			} catch (err) {
				expect(err.message).to.match(/No workspace manifests found/)
			}
		} finally {
			fs.rmSync(tmpDir, { recursive: true, force: true })
		}
	})

	test('discovers pnpm workspace packages', async () => {
		const pnpmYaml = `packages:\n  - 'apps/*'\n`
		const { root, cleanup } = createTmpWorkspace('pnpm_batch', {
			rootPkg: { name: 'pnpm-root', version: '1.0.0' },
			pnpmWorkspace: pnpmYaml,
			lockFile: 'pnpm-lock.yaml',
			packages: [
				{ dir: 'apps/web', content: { name: 'web', version: '1.0.0' } },
			],
		})

		try {
			const sbomMap = {}
			sbomMap[path.join(root, 'apps/web/package.json')] = makeSbom('web', '1.0.0')

			const mockProviders = buildMockProviders(sbomMap)
			const client = await esmock('../src/index.js', {
				'../src/provider.js': mockProviders,
			})

			const result = await client.stackAnalysisBatch(root, false, BACKEND_OPTS)

			expect(result).to.be.an('object')
			expect(capturedBody).to.be.an('object')
			expect(Object.keys(capturedBody)).to.include('pkg:npm/web@1.0.0')
		} finally {
			cleanup()
		}
	})
})
