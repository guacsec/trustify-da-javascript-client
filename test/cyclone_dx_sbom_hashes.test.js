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

	/** Verifies that attachHashes enriches an existing component matched by PURL. */
	test('attachHashes attaches hashes to a matching component by PURL', () => {
		// Given an SBOM with a dependency added without hashes
		const sbom = new CycloneDxSbom()
		const root = new PackageURL('maven', 'com.example', 'root', '1.0.0', undefined, undefined)
		const dep = new PackageURL('maven', 'log4j', 'log4j', '1.2.17', undefined, undefined)
		sbom.addRoot(root)
		sbom.addDependency(root, dep)

		// When attaching hashes keyed by the dependency's PURL
		sbom.attachHashes(new Map([[dep.toString(), sampleHashes]]))

		// Then the matching component carries the hashes
		const depComponent = sbom.components.find(c => c.name === 'log4j')
		expect(depComponent.hashes).to.deep.equal(sampleHashes)
	})

	/** Verifies that attachHashes leaves components without a map entry untouched. */
	test('attachHashes leaves unmatched components without a hashes field', () => {
		// Given an SBOM whose dependency has no entry in the hash map
		const sbom = new CycloneDxSbom()
		const root = new PackageURL('maven', 'com.example', 'root', '1.0.0', undefined, undefined)
		const dep = new PackageURL('maven', 'log4j', 'log4j', '1.2.17', undefined, undefined)
		sbom.addRoot(root)
		sbom.addDependency(root, dep)

		// When attaching a map that references a different PURL
		const other = new PackageURL('maven', 'com.other', 'lib', '9.9.9', undefined, undefined)
		sbom.attachHashes(new Map([[other.toString(), sampleHashes]]))

		// Then the unmatched component has no hashes property
		const depComponent = sbom.components.find(c => c.name === 'log4j')
		expect(depComponent).to.not.have.property('hashes')
	})

	/** Verifies that attachHashes does not overwrite hashes already present on a component. */
	test('attachHashes does not overwrite existing hashes', () => {
		// Given a component that already has hashes
		const sbom = new CycloneDxSbom()
		const root = new PackageURL('maven', 'com.example', 'root', '1.0.0', undefined, undefined)
		const dep = new PackageURL('maven', 'log4j', 'log4j', '1.2.17', undefined, undefined)
		const originalHashes = [{ alg: 'SHA-256', content: 'original' }]
		sbom.addRoot(root)
		sbom.addDependency(root, dep, undefined, originalHashes)

		// When attaching a different hash for the same PURL
		sbom.attachHashes(new Map([[dep.toString(), sampleHashes]]))

		// Then the original hashes are preserved
		const depComponent = sbom.components.find(c => c.name === 'log4j')
		expect(depComponent.hashes).to.deep.equal(originalHashes)
	})

	/** Verifies that attachHashes tolerates an undefined or empty map without error. */
	test('attachHashes is a no-op for an empty or undefined map', () => {
		// Given an SBOM with a dependency
		const sbom = new CycloneDxSbom()
		const root = new PackageURL('maven', 'com.example', 'root', '1.0.0', undefined, undefined)
		const dep = new PackageURL('maven', 'log4j', 'log4j', '1.2.17', undefined, undefined)
		sbom.addRoot(root)
		sbom.addDependency(root, dep)

		// When attaching an empty map and an undefined map
		sbom.attachHashes(new Map())
		sbom.attachHashes(undefined)

		// Then no hashes are added and no error is thrown
		const depComponent = sbom.components.find(c => c.name === 'log4j')
		expect(depComponent).to.not.have.property('hashes')
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

suite('CycloneDX SBOM license validation', () => {

	/** Verifies that non-CycloneDX license objects (e.g., { workspace: true }) are filtered out. */
	test('addRoot filters out non-CycloneDX license objects', () => {
		// Given a license value that is an unresolved workspace inheritance marker
		const sbom = new CycloneDxSbom()
		const root = new PackageURL('cargo', undefined, 'my-crate', '1.0.0', undefined, undefined)

		// When adding a root with a non-CycloneDX license object
		sbom.addRoot(root, { workspace: true })

		// Then the root component should have no licenses field
		expect(sbom.rootComponent).to.not.have.property('licenses')
	})

	/** Verifies that valid CycloneDX license objects are preserved. */
	test('addRoot preserves valid CycloneDX license objects', () => {
		const sbom = new CycloneDxSbom()
		const root = new PackageURL('cargo', undefined, 'my-crate', '1.0.0', undefined, undefined)
		sbom.addRoot(root, { license: { id: 'MIT' } })
		expect(sbom.rootComponent.licenses).to.deep.equal([{ license: { id: 'MIT' } }])
	})

	/** Verifies that string licenses are wrapped in CycloneDX format. */
	test('addRoot wraps string license in CycloneDX format', () => {
		const sbom = new CycloneDxSbom()
		const root = new PackageURL('cargo', undefined, 'my-crate', '1.0.0', undefined, undefined)
		sbom.addRoot(root, 'Apache-2.0')
		expect(sbom.rootComponent.licenses).to.deep.equal([{ license: { id: 'Apache-2.0' } }])
	})
})
