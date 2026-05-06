import { expect } from 'chai'
import { PackageURL } from 'packageurl-js'

import CycloneDxSbom from '../src/cyclone_dx_sbom.js'

const sampleHashes = [{ alg: 'SHA-256', content: 'abc123def456' }]

suite('CycloneDX SBOM hash support', () => {

	/** Verifies that addDependency with hashes produces a component containing the hashes array. */
	test('getComponent with hashes includes hashes array in component', () => {
		// Given an SBOM with a root and a dependency with hashes
		const sbom = new CycloneDxSbom()
		const root = new PackageURL('pypi', undefined, 'my-app', '1.0.0', undefined, undefined)
		const purl = new PackageURL('pypi', undefined, 'requests', '2.33.1', undefined, undefined)
		sbom.addRoot(root)

		// When adding a dependency with hashes
		sbom.addDependency(root, purl, undefined, sampleHashes)

		// Then the target component should include the hashes
		const targetComponent = sbom.components.find(c => c.name === 'requests')
		expect(targetComponent).to.exist
		expect(targetComponent.hashes).to.deep.equal(sampleHashes)
	})

	/** Verifies that addDependency without hashes produces a component with no hashes field. */
	test('getComponent without hashes does not include hashes field', () => {
		// Given an SBOM with a root and a dependency without hashes
		const sbom = new CycloneDxSbom()
		const root = new PackageURL('pypi', undefined, 'my-app', '1.0.0', undefined, undefined)
		const dep = new PackageURL('pypi', undefined, 'requests', '2.33.1', undefined, undefined)
		sbom.addRoot(root)

		// When adding a dependency without hashes
		sbom.addDependency(root, dep)

		// Then the target component should not have a hashes property
		const targetComponent = sbom.components.find(c => c.name === 'requests')
		expect(targetComponent).to.exist
		expect(targetComponent).to.not.have.property('hashes')
	})

	/** Verifies that hashes are attached only to the target component, not the source. */
	test('addDependency forwards hashes only to target component', () => {
		// Given an SBOM with a chain: root -> dep1 -> dep2 (only dep2 has hashes)
		const sbom = new CycloneDxSbom()
		const root = new PackageURL('pypi', undefined, 'my-app', '1.0.0', undefined, undefined)
		const dep1 = new PackageURL('pypi', undefined, 'requests', '2.33.1', undefined, undefined)
		const dep2 = new PackageURL('pypi', undefined, 'numpy', '1.24.0', undefined, undefined)
		const dep2Hashes = [{ alg: 'SHA-256', content: '789xyz' }]
		sbom.addRoot(root)
		sbom.addDependency(root, dep1)

		// When adding dep2 as a dependency of dep1 with hashes
		sbom.addDependency(dep1, dep2, undefined, dep2Hashes)

		// Then dep1 (source) should have no hashes, dep2 (target) should have hashes
		const dep1Component = sbom.components.find(c => c.name === 'requests')
		expect(dep1Component).to.not.have.property('hashes')
		const dep2Component = sbom.components.find(c => c.name === 'numpy')
		expect(dep2Component.hashes).to.deep.equal(dep2Hashes)
	})

	/** Verifies that hashes are included in the serialized CycloneDX JSON output. */
	test('hashes appear in serialized SBOM JSON', () => {
		// Given an SBOM with a hashed dependency
		const sbom = new CycloneDxSbom()
		const root = new PackageURL('pypi', undefined, 'my-app', '1.0.0', undefined, undefined)
		const dep = new PackageURL('pypi', undefined, 'requests', '2.33.1', undefined, undefined)
		sbom.addRoot(root)
		sbom.addDependency(root, dep, undefined, sampleHashes)

		// When serializing to JSON
		const json = JSON.parse(sbom.getAsJsonString({}))

		// Then the component in JSON should contain hashes
		const comp = json.components.find(c => c.name === 'requests')
		expect(comp.hashes).to.deep.equal(sampleHashes)
	})

	/** Verifies that components without hashes have no hashes field in serialized JSON. */
	test('component without hashes has no hashes in serialized SBOM JSON', () => {
		// Given an SBOM with a dependency without hashes
		const sbom = new CycloneDxSbom()
		const root = new PackageURL('pypi', undefined, 'my-app', '1.0.0', undefined, undefined)
		const dep = new PackageURL('pypi', undefined, 'requests', '2.33.1', undefined, undefined)
		sbom.addRoot(root)
		sbom.addDependency(root, dep)

		// When serializing to JSON
		const json = JSON.parse(sbom.getAsJsonString({}))

		// Then the component in JSON should not have a hashes property
		const comp = json.components.find(c => c.name === 'requests')
		expect(comp).to.not.have.property('hashes')
	})

	/** Verifies that hashes are applied to an existing component that was first created without them as a source. */
	test('hashes are updated on component first seen as source without hashes', () => {
		// Given a component first created as a source (without hashes)
		const sbom = new CycloneDxSbom()
		const root = new PackageURL('pypi', undefined, 'my-app', '1.0.0', undefined, undefined)
		const mid = new PackageURL('pypi', undefined, 'requests', '2.33.1', undefined, undefined)
		const leaf = new PackageURL('pypi', undefined, 'urllib3', '2.0.0', undefined, undefined)
		const midHashes = [{ alg: 'SHA-256', content: 'abc123' }]
		sbom.addRoot(root)

		// When mid is first seen as a source (no hashes), then as a target with hashes
		sbom.addDependency(mid, leaf)
		sbom.addDependency(root, mid, undefined, midHashes)

		// Then mid should have hashes despite being created first without them
		const midComponent = sbom.components.find(c => c.name === 'requests')
		expect(midComponent.hashes).to.deep.equal(midHashes)
	})

	/** Verifies that hashes are applied when a component already exists as a target without hashes. */
	test('hashes are updated on component first seen as target without hashes', () => {
		// Given a component first added as a target without hashes
		const sbom = new CycloneDxSbom()
		const root = new PackageURL('pypi', undefined, 'my-app', '1.0.0', undefined, undefined)
		const dep = new PackageURL('pypi', undefined, 'requests', '2.33.1', undefined, undefined)
		const depHashes = [{ alg: 'SHA-256', content: 'abc123' }]
		sbom.addRoot(root)
		sbom.addDependency(root, dep)

		// When the same component is added again as a target with hashes
		const other = new PackageURL('pypi', undefined, 'other', '1.0.0', undefined, undefined)
		sbom.addDependency(other, dep, undefined, depHashes)

		// Then the component should have hashes and not be duplicated
		const depComponents = sbom.components.filter(c => c.name === 'requests')
		expect(depComponents).to.have.lengthOf(1)
		expect(depComponents[0].hashes).to.deep.equal(depHashes)
	})

	/** Verifies that passing an empty hashes array is treated the same as no hashes. */
	test('empty hashes array does not add hashes field', () => {
		// Given an SBOM with a dependency with an empty hashes array
		const sbom = new CycloneDxSbom()
		const root = new PackageURL('pypi', undefined, 'my-app', '1.0.0', undefined, undefined)
		const dep = new PackageURL('pypi', undefined, 'requests', '2.33.1', undefined, undefined)
		sbom.addRoot(root)

		// When adding a dependency with empty hashes
		sbom.addDependency(root, dep, undefined, [])

		// Then the component should not have a hashes property
		const targetComponent = sbom.components.find(c => c.name === 'requests')
		expect(targetComponent).to.not.have.property('hashes')
	})
})
