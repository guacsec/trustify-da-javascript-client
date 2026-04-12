import fs from 'node:fs'
import { expect } from 'chai'
import esmock from 'esmock'

function makeSbom(name, version) {
	return {
		metadata: {
			component: {
				purl: `pkg:npm/${name}@${version}`,
				'bom-ref': `pkg:npm/${name}@${version}`,
			},
		},
		components: [
			{ name: 'dep-a', version: '1.0.0', purl: 'pkg:npm/dep-a@1.0.0' },
		],
	}
}

function buildMockProviders(sbomMap) {
	const mockProvider = {
		isSupported: () => true,
		validateLockFile: () => true,
		provideStack: (manifestPath) => {
			const sbom = sbomMap[manifestPath]
			if (!sbom) {
				throw new Error(`Unsupported manifest: ${manifestPath}`)
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

async function createMockClient(sbomMap) {
	return esmock('../src/index.js', {
		'../src/provider.js': buildMockProviders(sbomMap),
		'node:fs': {
			...fs,
			default: { ...fs, accessSync: () => {} },
			accessSync: () => {},
		},
	})
}

suite('testing generateSbom', () => {
	test('returns valid CycloneDX JSON for a pom.xml manifest', async () => {
		const expected = makeSbom('my-app', '1.0.0')
		const client = await createMockClient({ '/fake/pom.xml': expected })
		const result = await client.generateSbom('/fake/pom.xml')
		expect(result).to.deep.equal(expected)
		expect(result.metadata.component.purl).to.equal('pkg:npm/my-app@1.0.0')
	})

	test('returns valid CycloneDX JSON for a package.json manifest', async () => {
		const expected = makeSbom('my-js-app', '2.0.0')
		const client = await createMockClient({ '/fake/package.json': expected })
		const result = await client.generateSbom('/fake/package.json')
		expect(result).to.deep.equal(expected)
		expect(result.metadata.component.purl).to.equal('pkg:npm/my-js-app@2.0.0')
	})

	test('throws for unsupported manifest types', async () => {
		const client = await createMockClient({})
		try {
			await client.generateSbom('/fake/unsupported.txt')
			expect.fail('should have thrown')
		} catch (err) {
			expect(err.message).to.include('Unsupported manifest')
		}
	})

	test('generated SBOM contains metadata.component with expected purl', async () => {
		const expected = makeSbom('test-pkg', '3.5.1')
		const client = await createMockClient({ '/project/pom.xml': expected })
		const result = await client.generateSbom('/project/pom.xml')
		expect(result.metadata).to.exist
		expect(result.metadata.component).to.exist
		expect(result.metadata.component.purl).to.equal('pkg:npm/test-pkg@3.5.1')
		expect(result.components).to.be.an('array').with.lengthOf(1)
		expect(result.components[0].name).to.equal('dep-a')
	})

	test('throws when SBOM is missing purl', async () => {
		const sbomNoPurl = {
			metadata: {
				component: {
					name: 'no-purl-app',
				},
			},
			components: [],
		}
		const client = await createMockClient({ '/fake/pom.xml': sbomNoPurl })
		try {
			await client.generateSbom('/fake/pom.xml')
			expect.fail('should have thrown')
		} catch (err) {
			expect(err.message).to.include('missing purl in SBOM')
		}
	})
})
