import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { expect } from 'chai'

import { updateTomlVersions } from '../../src/updaters/toml_updater.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const FIXTURES_DIR = path.join(__dirname, 'fixtures')

/**
 * Reads the sample libs.versions.toml fixture.
 * @returns {string} raw TOML content
 */
function loadFixture() {
	return fs.readFileSync(path.join(FIXTURES_DIR, 'libs.versions.toml'), 'utf-8')
}

suite('toml_updater — updateTomlVersions', () => {

	suite('centralized version updates (version.ref)', () => {

		/** Verifies that a version in the [versions] section is updated when a library uses version.ref. */
		test('updates a version in [versions] for a library with version.ref', () => {
			// Given a TOML with quarkus-resteasy referencing version.ref = "quarkus"
			const toml = loadFixture()
			const changes = [{ groupId: 'io.quarkus', artifactId: 'quarkus-resteasy', newVersion: '3.9.0' }]

			// When updating
			const result = updateTomlVersions(toml, changes)

			// Then the [versions] quarkus entry is updated
			expect(result.applied).to.have.lengthOf(1)
			expect(result.applied[0]).to.deep.include({
				groupId: 'io.quarkus',
				artifactId: 'quarkus-resteasy',
				newVersion: '3.9.0',
				oldVersion: '3.8.4'
			})
			expect(result.skipped).to.have.lengthOf(0)
			expect(result.content).to.include('quarkus = "3.9.0"')
			expect(result.content).not.to.include('quarkus = "3.8.4"')
		})

		/** Verifies that updating one library sharing a version.ref also affects other libraries using the same ref. */
		test('updates shared version ref affecting multiple libraries', () => {
			// Given quarkus-resteasy and quarkus-arc both use version.ref = "quarkus"
			const toml = loadFixture()
			const changes = [{ groupId: 'io.quarkus', artifactId: 'quarkus-arc', newVersion: '3.10.0' }]

			// When updating via quarkus-arc
			const result = updateTomlVersions(toml, changes)

			// Then the shared [versions] quarkus entry is updated
			expect(result.applied).to.have.lengthOf(1)
			expect(result.content).to.include('quarkus = "3.10.0"')
		})

		/** Verifies updating a different centralized version (jackson). */
		test('updates jackson version via centralized ref', () => {
			const toml = loadFixture()
			const changes = [{ groupId: 'com.fasterxml.jackson.core', artifactId: 'jackson-databind', newVersion: '2.18.0' }]

			const result = updateTomlVersions(toml, changes)

			expect(result.applied).to.have.lengthOf(1)
			expect(result.applied[0].oldVersion).to.equal('2.17.0')
			expect(result.content).to.include('jackson = "2.18.0"')
		})
	})

	suite('inline version updates', () => {

		/** Verifies that an inline version = "x.y.z" on a library entry is updated directly. */
		test('updates an inline version on a library entry', () => {
			// Given guava has an inline version = "33.1.0-jre"
			const toml = loadFixture()
			const changes = [{ groupId: 'com.google.guava', artifactId: 'guava', newVersion: '33.2.0-jre' }]

			// When updating
			const result = updateTomlVersions(toml, changes)

			// Then the inline version is updated in the library entry
			expect(result.applied).to.have.lengthOf(1)
			expect(result.applied[0]).to.deep.include({
				groupId: 'com.google.guava',
				artifactId: 'guava',
				newVersion: '33.2.0-jre',
				oldVersion: '33.1.0-jre'
			})
			expect(result.content).to.include('version = "33.2.0-jre"')
			expect(result.content).not.to.include('version = "33.1.0-jre"')
		})

		/** Verifies update of a second inline-versioned library. */
		test('updates inline version for commons-lang3', () => {
			const toml = loadFixture()
			const changes = [{ groupId: 'org.apache.commons', artifactId: 'commons-lang3', newVersion: '3.15.0' }]

			const result = updateTomlVersions(toml, changes)

			expect(result.applied).to.have.lengthOf(1)
			expect(result.applied[0].oldVersion).to.equal('3.14.0')
			expect(result.content).to.include('version = "3.15.0"')
		})

		/** Verifies update of a string shorthand notation "group:artifact:version". */
		test('updates string shorthand notation', () => {
			const toml = loadFixture()
			const changes = [{ groupId: 'org.junit.jupiter', artifactId: 'junit-jupiter', newVersion: '5.11.0' }]

			const result = updateTomlVersions(toml, changes)

			expect(result.applied).to.have.lengthOf(1)
			expect(result.applied[0].oldVersion).to.equal('5.10.2')
			expect(result.content).to.include('junit = "org.junit.jupiter:junit-jupiter:5.11.0"')
		})
	})

	suite('unmatched and no-op cases', () => {

		/** Verifies that a library not present in the catalog is skipped with explanation. */
		test('skips a library not present in the catalog', () => {
			const toml = loadFixture()
			const changes = [{ groupId: 'org.nonexistent', artifactId: 'fake-lib', newVersion: '1.0.0' }]

			const result = updateTomlVersions(toml, changes)

			expect(result.applied).to.have.lengthOf(0)
			expect(result.skipped).to.have.lengthOf(1)
			expect(result.skipped[0].reason).to.include('No library entry found')
			expect(result.content).to.equal(toml)
		})

		/** Verifies that a library already at the requested version is skipped. */
		test('skips when version already matches', () => {
			const toml = loadFixture()
			const changes = [{ groupId: 'io.quarkus', artifactId: 'quarkus-resteasy', newVersion: '3.8.4' }]

			const result = updateTomlVersions(toml, changes)

			expect(result.applied).to.have.lengthOf(0)
			expect(result.skipped).to.have.lengthOf(1)
			expect(result.skipped[0].reason).to.include('already at')
			expect(result.content).to.equal(toml)
		})

		/** Verifies that a library without any version (BOM-managed) is skipped. */
		test('skips a library with no version (BOM-managed)', () => {
			const toml = loadFixture()
			const changes = [{ groupId: 'org.projectlombok', artifactId: 'lombok', newVersion: '1.18.34' }]

			const result = updateTomlVersions(toml, changes)

			expect(result.applied).to.have.lengthOf(0)
			expect(result.skipped).to.have.lengthOf(1)
			expect(result.skipped[0].reason).to.include('No version.ref or inline version')
		})

		/** Verifies that empty versionChanges produces no modifications. */
		test('returns original content with empty versionChanges', () => {
			const toml = loadFixture()

			const result = updateTomlVersions(toml, [])

			expect(result.content).to.equal(toml)
			expect(result.applied).to.have.lengthOf(0)
			expect(result.skipped).to.have.lengthOf(0)
		})

		/** Verifies that null versionChanges is handled gracefully. */
		test('handles null versionChanges', () => {
			const toml = loadFixture()

			const result = updateTomlVersions(toml, null)

			expect(result.content).to.equal(toml)
			expect(result.applied).to.have.lengthOf(0)
			expect(result.skipped).to.have.lengthOf(0)
		})
	})

	suite('formatting and comment preservation', () => {

		/** Verifies that TOML comments survive version updates. */
		test('preserves comments', () => {
			const toml = loadFixture()
			const changes = [{ groupId: 'io.quarkus', artifactId: 'quarkus-resteasy', newVersion: '3.9.0' }]

			const result = updateTomlVersions(toml, changes)

			expect(result.content).to.include('# Gradle version catalog for testing TOML updater')
			expect(result.content).to.include('# Centralized version references')
			expect(result.content).to.include('# Inline version')
			expect(result.content).to.include('# String shorthand notation')
			expect(result.content).to.include('# No version (BOM-managed)')
		})

		/** Verifies that section headers, bundles, and plugins remain intact. */
		test('preserves section headers, bundles, and plugins', () => {
			const toml = loadFixture()
			const changes = [{ groupId: 'io.quarkus', artifactId: 'quarkus-resteasy', newVersion: '3.9.0' }]

			const result = updateTomlVersions(toml, changes)

			expect(result.content).to.include('[versions]')
			expect(result.content).to.include('[libraries]')
			expect(result.content).to.include('[bundles]')
			expect(result.content).to.include('[plugins]')
			expect(result.content).to.include('quarkus = ["quarkus-resteasy", "quarkus-arc"]')
		})

		/** Verifies that non-targeted library entries remain unchanged. */
		test('leaves unmatched library entries unchanged', () => {
			const toml = loadFixture()
			const changes = [{ groupId: 'io.quarkus', artifactId: 'quarkus-resteasy', newVersion: '3.9.0' }]

			const result = updateTomlVersions(toml, changes)

			expect(result.content).to.include('jackson = "2.17.0"')
			expect(result.content).to.include('log4j = "2.23.1"')
			expect(result.content).to.include('version = "33.1.0-jre"')
		})
	})

	suite('idempotency', () => {

		/** Verifies that running updateTomlVersions twice with the same input produces the same output. */
		test('produces the same output when run twice', () => {
			const toml = loadFixture()
			const changes = [
				{ groupId: 'io.quarkus', artifactId: 'quarkus-resteasy', newVersion: '3.9.0' },
				{ groupId: 'com.google.guava', artifactId: 'guava', newVersion: '33.2.0-jre' }
			]

			const first = updateTomlVersions(toml, changes)
			const second = updateTomlVersions(first.content, changes)

			expect(second.content).to.equal(first.content)
			expect(second.applied).to.have.lengthOf(0)
			expect(second.skipped).to.have.lengthOf(2)
			second.skipped.forEach(s => expect(s.reason).to.include('already at'))
		})
	})

	suite('multiple changes in one call', () => {

		/** Verifies that multiple version changes are applied in a single call. */
		test('applies multiple changes mixing centralized and inline', () => {
			const toml = loadFixture()
			const changes = [
				{ groupId: 'io.quarkus', artifactId: 'quarkus-resteasy', newVersion: '3.9.0' },
				{ groupId: 'com.google.guava', artifactId: 'guava', newVersion: '33.2.0-jre' },
				{ groupId: 'org.nonexistent', artifactId: 'nope', newVersion: '1.0.0' }
			]

			const result = updateTomlVersions(toml, changes)

			expect(result.applied).to.have.lengthOf(2)
			expect(result.skipped).to.have.lengthOf(1)
			expect(result.content).to.include('quarkus = "3.9.0"')
			expect(result.content).to.include('version = "33.2.0-jre"')
		})
	})

	suite('malformed TOML handling', () => {

		/** Verifies that invalid TOML is handled gracefully with all changes skipped. */
		test('returns original content and skips all changes for malformed TOML', () => {
			const badToml = '[versions\nquarkus = "broken'
			const changes = [{ groupId: 'io.quarkus', artifactId: 'quarkus-resteasy', newVersion: '3.9.0' }]

			const result = updateTomlVersions(badToml, changes)

			expect(result.content).to.equal(badToml)
			expect(result.applied).to.have.lengthOf(0)
			expect(result.skipped).to.have.lengthOf(1)
			expect(result.skipped[0].reason).to.include('Failed to parse TOML')
		})

		/** Verifies that empty TOML content is handled without errors. */
		test('handles empty TOML content', () => {
			const changes = [{ groupId: 'io.quarkus', artifactId: 'quarkus-resteasy', newVersion: '3.9.0' }]

			const result = updateTomlVersions('', changes)

			expect(result.applied).to.have.lengthOf(0)
			expect(result.skipped).to.have.lengthOf(1)
			expect(result.skipped[0].reason).to.include('No library entry found')
		})

		/** Verifies handling of TOML with [libraries] but no [versions]. */
		test('handles TOML with libraries referencing missing versions section', () => {
			const toml = `[libraries]
mylib = { module = "com.example:mylib", version.ref = "mylib-version" }
`
			const changes = [{ groupId: 'com.example', artifactId: 'mylib', newVersion: '2.0.0' }]

			const result = updateTomlVersions(toml, changes)

			expect(result.applied).to.have.lengthOf(0)
			expect(result.skipped).to.have.lengthOf(1)
			expect(result.skipped[0].reason).to.include('not found in [versions]')
		})
	})

	suite('edge cases', () => {

		/** Verifies that group/name notation (non-module) is supported. */
		test('handles group/name notation in library entries', () => {
			const toml = `[versions]
myver = "1.0.0"

[libraries]
mylib = { group = "com.example", name = "mylib", version.ref = "myver" }
`
			const changes = [{ groupId: 'com.example', artifactId: 'mylib', newVersion: '2.0.0' }]

			const result = updateTomlVersions(toml, changes)

			expect(result.applied).to.have.lengthOf(1)
			expect(result.applied[0].oldVersion).to.equal('1.0.0')
			expect(result.content).to.include('myver = "2.0.0"')
		})

		/** Verifies that $ in newVersion is not interpreted as a regex replacement pattern. */
		test('handles $ characters in newVersion without corruption', () => {
			const toml = `[versions]
myver = "1.0.0"

[libraries]
mylib = { module = "com.example:mylib", version.ref = "myver" }
`
			const changes = [{ groupId: 'com.example', artifactId: 'mylib', newVersion: 'ver$1ify' }]

			const result = updateTomlVersions(toml, changes)

			expect(result.applied).to.have.lengthOf(1)
			expect(result.content).to.include('myver = "ver$1ify"')
		})

		/** Verifies that $$ and $& in newVersion are treated as literal characters. */
		test('handles $$ and $& in newVersion for inline versions', () => {
			const toml = `[libraries]
mylib = { module = "com.example:mylib", version = "1.0.0" }
`
			const changes = [{ groupId: 'com.example', artifactId: 'mylib', newVersion: 'price$$5' }]

			const result = updateTomlVersions(toml, changes)

			expect(result.applied).to.have.lengthOf(1)
			expect(result.content).to.include('version = "price$$5"')
		})

		/** Verifies that $1 in newVersion works for string shorthand notation. */
		test('handles $ in newVersion for string shorthand', () => {
			const toml = `[libraries]
mylib = "com.example:mylib:1.0.0"
`
			const changes = [{ groupId: 'com.example', artifactId: 'mylib', newVersion: '2.0.0-$TAG' }]

			const result = updateTomlVersions(toml, changes)

			expect(result.applied).to.have.lengthOf(1)
			expect(result.content).to.include('mylib = "com.example:mylib:2.0.0-$TAG"')
		})

		/** Verifies that an inline version with a trailing comment that breaks the regex is reported as skipped. */
		test('reports skipped when inline version regex does not match', () => {
			// Given a library entry with a trailing comment after the closing brace
			// smol-toml parses this correctly but the replacement regex expects }$ at end-of-line
			const toml = `[libraries]
mylib = { module = "com.example:mylib", version = "1.0.0" } # pinned
`
			const changes = [{ groupId: 'com.example', artifactId: 'mylib', newVersion: '2.0.0' }]

			// When attempting to update
			const result = updateTomlVersions(toml, changes)

			// Then the change should be reported as skipped, not applied
			expect(result.applied).to.have.lengthOf(0)
			expect(result.skipped).to.have.lengthOf(1)
			expect(result.skipped[0].reason).to.include('did not match')
			expect(result.content).to.equal(toml)
		})

		/** Verifies that versions with special characters (dots, hyphens) are handled correctly. */
		test('handles version strings with dots, hyphens, and qualifiers', () => {
			const toml = `[versions]
quarkus = "2.13.5.Final"

[libraries]
quarkus-core = { module = "io.quarkus:quarkus-core", version.ref = "quarkus" }
`
			const changes = [{ groupId: 'io.quarkus', artifactId: 'quarkus-core', newVersion: '3.0.0.Final' }]

			const result = updateTomlVersions(toml, changes)

			expect(result.applied).to.have.lengthOf(1)
			expect(result.content).to.include('quarkus = "3.0.0.Final"')
			expect(result.content).not.to.include('2.13.5.Final')
		})
	})
})
