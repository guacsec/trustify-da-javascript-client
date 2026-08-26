import fs from 'node:fs'
import { createRequire } from 'node:module'

import Ajv from 'ajv'
import { expect } from 'chai'
import { PackageURL } from 'packageurl-js'

import CycloneDxSbom from '../src/cyclone_dx_sbom.js'

const require = createRequire(import.meta.url)

/** This client's version, used to assert the tool metadata reported in the SBOM. */
const packageVersion = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url)).toString()).version

/**
 * Builds an ajv validator for the CycloneDX 1.6 JSON schema bundled with
 * @cyclonedx/cyclonedx-library. Formats are not validated (the referenced
 * format checkers are optional deps) — this exercises structure and enums,
 * which is what catches an invalid tool component `type`.
 * @return {(obj: object) => boolean} the compiled validator
 */
function buildCycloneDx16Validator() {
	const schemaDir = require.resolve('@cyclonedx/cyclonedx-library/package.json').replace(/package\.json$/, 'res/schema/')
	const load = name => JSON.parse(fs.readFileSync(schemaDir + name, 'utf8'))
	const bom = load('bom-1.6.SNAPSHOT.schema.json')
	delete bom.$id // resolve the relative $refs against the plain schema keys below
	const ajv = new Ajv({ strict: false, validateFormats: false, addUsedSchema: false })
	ajv.addSchema(load('spdx.SNAPSHOT.schema.json'), 'spdx.SNAPSHOT.schema.json')
	ajv.addSchema(load('jsf-0.82.SNAPSHOT.schema.json'), 'jsf-0.82.SNAPSHOT.schema.json')
	return ajv.compile(bom)
}

/**
 * Creates a minimal SBOM with a root and one dependency.
 * @return {CycloneDxSbom} the populated SBOM
 */
function sampleSbom() {
	const sbom = new CycloneDxSbom()
	const root = new PackageURL('npm', undefined, 'my-app', '1.0.0', undefined, undefined)
	const dep = new PackageURL('npm', undefined, 'axios', '0.21.1', undefined, undefined)
	sbom.addRoot(root)
	sbom.addDependency(root, dep)
	return sbom
}

suite('CycloneDX SBOM spec version and tool metadata', () => {

	/** Verifies the generated SBOM declares CycloneDX spec version 1.6. */
	test('generated SBOM has specVersion 1.6', () => {
		const json = JSON.parse(sampleSbom().getAsJsonString({}))
		expect(json.specVersion).to.equal('1.6')
	})

	/** Verifies metadata.tools uses the 1.5+ object format with the correct tool name and version. */
	test('metadata.tools.components carries the tool name and version', () => {
		// Given a populated SBOM
		const sbom = sampleSbom()

		// When serializing to JSON
		const json = JSON.parse(sbom.getAsJsonString({}))

		// Then metadata.tools is the {components: [...]} object form with this client as the tool
		expect(json.metadata.tools).to.deep.equal({
			components: [{
				type: 'application',
				name: 'trustify-da-javascript-client',
				version: packageVersion
			}]
		})
	})

	/** Verifies tool metadata is present even when the SBOM has no root component. */
	test('metadata.tools is present when there is no root component', () => {
		// Given an SBOM with only a dependency (no root)
		const sbom = new CycloneDxSbom()
		const a = new PackageURL('npm', undefined, 'a', '1.0.0', undefined, undefined)
		const b = new PackageURL('npm', undefined, 'b', '2.0.0', undefined, undefined)
		sbom.addDependency(a, b)

		// When serializing to JSON
		const json = JSON.parse(sbom.getAsJsonString({}))

		// Then the tool metadata is still emitted
		expect(json.metadata.component).to.be.undefined
		expect(json.metadata.tools.components[0].name).to.equal('trustify-da-javascript-client')
	})
})

suite('CycloneDX SBOM schema validation', () => {

	/** Verifies the generated SBOM validates against the CycloneDX 1.6 JSON schema. */
	test('generated SBOM validates against the CycloneDX 1.6 schema', () => {
		// Given the CycloneDX 1.6 schema validator and a generated SBOM
		const validate = buildCycloneDx16Validator()
		const json = JSON.parse(sampleSbom().getAsJsonString({ 'manifest-type': 'package.json' }))

		// When validating the SBOM
		const valid = validate(json)

		// Then it conforms to the schema
		expect(valid, JSON.stringify(validate.errors)).to.be.true
	})

	/** Verifies the validator rejects a tool component whose type is not a valid enum value. */
	test('schema validation rejects an invalid tool component type', () => {
		// Given a generated SBOM with a typo'd tool component type
		const validate = buildCycloneDx16Validator()
		const json = JSON.parse(sampleSbom().getAsJsonString({}))
		json.metadata.tools.components[0].type = 'app'

		// When validating the SBOM
		const valid = validate(json)

		// Then the schema rejects it
		expect(valid).to.be.false
	})
})
