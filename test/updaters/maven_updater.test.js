import fs from 'node:fs';
import path from 'node:path';

import { expect } from 'chai';

import { updateMavenVersions } from '../../src/updaters/maven_updater.js';

const fixturesDir = path.resolve('test/updaters/fixtures');

/** Reads a fixture file and returns its content as a string. */
function loadFixture(name) {
	return fs.readFileSync(path.join(fixturesDir, name), 'utf-8');
}

suite('maven_updater', () => {

	suite('direct version replacement', () => {

		/** Verifies that a single dependency with a direct version is updated. */
		test('updates a single dependency version', () => {
			// Given
			const pom = loadFixture('pom_direct_versions.xml');

			// When
			const result = updateMavenVersions(pom, [
				{ groupId: 'com.example', artifactId: 'lib-a', newVersion: '2.0.0' },
			]);

			// Then
			expect(result.applied).to.have.lengthOf(1);
			expect(result.applied[0]).to.deep.include({
				groupId: 'com.example',
				artifactId: 'lib-a',
				newVersion: '2.0.0',
				type: 'direct',
			});
			expect(result.skipped).to.have.lengthOf(0);
			expect(result.content).to.include(
				'<artifactId>lib-a</artifactId>\n            <version>2.0.0</version>'
			);
		});

		/** Verifies that multiple direct versions are updated in a single call. */
		test('updates multiple dependency versions', () => {
			// Given
			const pom = loadFixture('pom_direct_versions.xml');

			// When
			const result = updateMavenVersions(pom, [
				{ groupId: 'com.example', artifactId: 'lib-a', newVersion: '2.0.0' },
				{ groupId: 'com.example', artifactId: 'lib-b', newVersion: '3.0.0' },
			]);

			// Then
			expect(result.applied).to.have.lengthOf(2);
			expect(result.skipped).to.have.lengthOf(0);
			expect(result.content).to.include('<version>2.0.0</version>');
			expect(result.content).to.include('<version>3.0.0</version>');
			expect(result.content).not.to.include('<version>1.0.0</version>');
			expect(result.content).not.to.include('<version>2.3.4</version>');
		});
	});

	suite('property-based version replacement', () => {

		/** Verifies that a ${property} reference is traced to <properties> and updated there. */
		test('traces ${property} and updates the property value', () => {
			// Given
			const pom = loadFixture('pom_property_versions.xml');

			// When
			const result = updateMavenVersions(pom, [
				{ groupId: 'com.fasterxml.jackson.core', artifactId: 'jackson-databind', newVersion: '2.16.0' },
			]);

			// Then
			expect(result.applied).to.have.lengthOf(1);
			expect(result.applied[0]).to.deep.include({
				type: 'property',
				property: 'jackson.version',
			});
			expect(result.skipped).to.have.lengthOf(0);
			expect(result.content).to.include('<jackson.version>2.16.0</jackson.version>');
			expect(result.content).to.include('${jackson.version}');
		});

		/** Verifies that two dependencies sharing a property cause only one replacement. */
		test('handles multiple deps sharing the same property', () => {
			// Given
			const pom = loadFixture('pom_property_versions.xml');

			// When
			const result = updateMavenVersions(pom, [
				{ groupId: 'com.fasterxml.jackson.core', artifactId: 'jackson-databind', newVersion: '2.16.0' },
				{ groupId: 'com.fasterxml.jackson.core', artifactId: 'jackson-core', newVersion: '2.16.0' },
			]);

			// Then
			expect(result.applied).to.have.lengthOf(2);
			expect(result.skipped).to.have.lengthOf(0);
			expect(result.content).to.include('<jackson.version>2.16.0</jackson.version>');
			// The property should appear only once
			const matches = result.content.match(/<jackson\.version>/g);
			expect(matches).to.have.lengthOf(1);
		});

		/** Verifies that conflicting versions for the same property are detected and skipped. */
		test('skips when shared property targeted with conflicting versions', () => {
			// Given
			const pom = loadFixture('pom_property_versions.xml');

			// When
			const result = updateMavenVersions(pom, [
				{ groupId: 'com.fasterxml.jackson.core', artifactId: 'jackson-databind', newVersion: '2.16.0' },
				{ groupId: 'com.fasterxml.jackson.core', artifactId: 'jackson-core', newVersion: '2.17.0' },
			]);

			// Then
			expect(result.applied).to.have.lengthOf(1);
			expect(result.skipped).to.have.lengthOf(1);
			expect(result.skipped[0].reason).to.include('already targeted');
			expect(result.skipped[0].reason).to.include('2.16.0');
		});
	});

	suite('recursive property chain', () => {

		/** Verifies that ${a} -> ${b} -> value is resolved and the terminal property updated. */
		test('resolves recursive property chain and updates terminal property', () => {
			// Given
			const pom = loadFixture('pom_recursive_properties.xml');

			// When
			const result = updateMavenVersions(pom, [
				{ groupId: 'com.example', artifactId: 'recursive-lib', newVersion: '2.0.0' },
			]);

			// Then
			expect(result.applied).to.have.lengthOf(1);
			expect(result.applied[0]).to.deep.include({
				type: 'property',
				property: 'base.version',
			});
			expect(result.skipped).to.have.lengthOf(0);
			expect(result.content).to.include('<base.version>2.0.0</base.version>');
			// Intermediate property reference preserved
			expect(result.content).to.include('<lib.version>${base.version}</lib.version>');
			// Dependency reference preserved
			expect(result.content).to.include('${lib.version}');
		});
	});

	suite('circular property reference', () => {

		/** Verifies that a circular property chain is detected and reported as skipped. */
		test('detects cycle and reports in skipped with error message', () => {
			// Given
			const pom = loadFixture('pom_circular_properties.xml');

			// When
			const result = updateMavenVersions(pom, [
				{ groupId: 'com.example', artifactId: 'circular-lib', newVersion: '1.0.0' },
			]);

			// Then
			expect(result.applied).to.have.lengthOf(0);
			expect(result.skipped).to.have.lengthOf(1);
			expect(result.skipped[0].reason).to.include('Circular property reference');
			expect(result.content).to.equal(pom);
		});
	});

	suite('formatting preservation', () => {

		/** Verifies that comments, indentation, whitespace, and unrelated content are preserved. */
		test('preserves comments, indentation, and whitespace', () => {
			// Given
			const pom = loadFixture('pom_with_comments.xml');

			// When
			const result = updateMavenVersions(pom, [
				{ groupId: 'com.example', artifactId: 'lib-a', newVersion: '2.0.0' },
				{ groupId: 'com.fasterxml.jackson.core', artifactId: 'jackson-databind', newVersion: '2.16.0' },
			]);

			// Then
			expect(result.applied).to.have.lengthOf(2);

			// Comments preserved
			expect(result.content).to.include('<!-- Project-level comment preserved across updates -->');
			expect(result.content).to.include('<!-- Jackson version for JSON processing -->');
			expect(result.content).to.include('<!-- Direct dependency with inline comment -->');
			expect(result.content).to.include('<!-- current version -->');
			expect(result.content).to.include('Multi-line comment block that should');

			// Untouched property preserved
			expect(result.content).to.include('<untouched.prop>keep-me</untouched.prop>');

			// Untouched dependency preserved
			expect(result.content).to.include('<version>9.9.9</version>');

			// Updated values present
			expect(result.content).to.include(
				'<artifactId>lib-a</artifactId>\n            <version>2.0.0</version>'
			);
			expect(result.content).to.include('<jackson.version>2.16.0</jackson.version>');
		});
	});

	suite('unchanged dependencies', () => {

		/** Verifies that dependencies not listed in versionChanges are left untouched. */
		test('leaves dependencies not in versionChanges untouched', () => {
			// Given
			const pom = loadFixture('pom_direct_versions.xml');

			// When
			const result = updateMavenVersions(pom, [
				{ groupId: 'com.example', artifactId: 'lib-a', newVersion: '2.0.0' },
			]);

			// Then
			expect(result.applied).to.have.lengthOf(1);
			// lib-b and unchanged-lib should retain their original versions
			expect(result.content).to.include(
				'<artifactId>lib-b</artifactId>\n            <version>2.3.4</version>'
			);
			expect(result.content).to.include(
				'<artifactId>unchanged-lib</artifactId>\n            <version>3.0.0</version>'
			);
		});
	});

	suite('error handling', () => {

		/** Verifies that malformed XML is handled gracefully without crashing. */
		test('handles malformed pom.xml gracefully', () => {
			// Given — fast-xml-parser v5 parses incomplete XML without throwing,
			// so the fail-safe path is: dependency not found => skipped
			const pom = loadFixture('pom_malformed.xml');

			// When
			const result = updateMavenVersions(pom, [
				{ groupId: 'com.example', artifactId: 'broken', newVersion: '1.0.0' },
			]);

			// Then
			expect(result.applied).to.have.lengthOf(0);
			expect(result.skipped).to.have.lengthOf(1);
			expect(result.skipped[0].reason).to.be.a('string');
			expect(result.content).to.equal(pom);
		});

		/** Verifies that a dependency not present in the file is reported as skipped. */
		test('reports missing dependency in skipped', () => {
			// Given
			const pom = loadFixture('pom_direct_versions.xml');

			// When
			const result = updateMavenVersions(pom, [
				{ groupId: 'com.nonexistent', artifactId: 'ghost-lib', newVersion: '1.0.0' },
			]);

			// Then
			expect(result.applied).to.have.lengthOf(0);
			expect(result.skipped).to.have.lengthOf(1);
			expect(result.skipped[0].reason).to.include('not found');
		});

		/** Verifies that a property reference to a non-existent property is skipped. */
		test('reports missing property in skipped', () => {
			// Given a pom with a dependency referencing a non-existent property
			const pom = [
				'<?xml version="1.0"?>',
				'<project>',
				'    <properties></properties>',
				'    <dependencies>',
				'        <dependency>',
				'            <groupId>com.example</groupId>',
				'            <artifactId>ghost-prop-lib</artifactId>',
				'            <version>${nonexistent.version}</version>',
				'        </dependency>',
				'    </dependencies>',
				'</project>',
			].join('\n');

			// When
			const result = updateMavenVersions(pom, [
				{ groupId: 'com.example', artifactId: 'ghost-prop-lib', newVersion: '1.0.0' },
			]);

			// Then
			expect(result.applied).to.have.lengthOf(0);
			expect(result.skipped).to.have.lengthOf(1);
			expect(result.skipped[0].reason).to.include("'nonexistent.version'");
			expect(result.skipped[0].reason).to.include('not found');
		});

		/** Verifies that empty versionChanges returns the content unchanged. */
		test('returns unchanged content for empty versionChanges', () => {
			// Given
			const pom = loadFixture('pom_direct_versions.xml');

			// When
			const result = updateMavenVersions(pom, []);

			// Then
			expect(result.applied).to.have.lengthOf(0);
			expect(result.skipped).to.have.lengthOf(0);
			expect(result.content).to.equal(pom);
		});

		/** Verifies that pom.xml without a <project> element skips all changes. */
		test('skips all changes when no <project> element exists', () => {
			// Given
			const pom = '<?xml version="1.0"?>\n<root><thing>value</thing></root>';

			// When
			const result = updateMavenVersions(pom, [
				{ groupId: 'com.example', artifactId: 'lib', newVersion: '1.0.0' },
			]);

			// Then
			expect(result.applied).to.have.lengthOf(0);
			expect(result.skipped).to.have.lengthOf(1);
			expect(result.skipped[0].reason).to.include('No <project> element');
			expect(result.content).to.equal(pom);
		});
	});

	suite('idempotency', () => {

		/** Verifies that running updateMavenVersions twice with the same input is idempotent. */
		test('running twice with same input produces same output', () => {
			// Given
			const pom = loadFixture('pom_direct_versions.xml');
			const changes = [
				{ groupId: 'com.example', artifactId: 'lib-a', newVersion: '2.0.0' },
				{ groupId: 'com.example', artifactId: 'lib-b', newVersion: '3.0.0' },
			];

			// When
			const first = updateMavenVersions(pom, changes);
			const second = updateMavenVersions(first.content, changes);

			// Then
			expect(second.content).to.equal(first.content);
			expect(second.applied).to.have.lengthOf(2);
			expect(second.skipped).to.have.lengthOf(0);
		});

		/** Verifies idempotency for property-based versions. */
		test('running twice with property versions produces same output', () => {
			// Given
			const pom = loadFixture('pom_property_versions.xml');
			const changes = [
				{ groupId: 'com.fasterxml.jackson.core', artifactId: 'jackson-databind', newVersion: '2.16.0' },
			];

			// When
			const first = updateMavenVersions(pom, changes);
			const second = updateMavenVersions(first.content, changes);

			// Then
			expect(second.content).to.equal(first.content);
		});
	});

	suite('dependencyManagement support', () => {

		/** Verifies that versions in <dependencyManagement> are updated. */
		test('updates version in dependencyManagement section', () => {
			// Given
			const pom = [
				'<?xml version="1.0"?>',
				'<project>',
				'    <dependencyManagement>',
				'        <dependencies>',
				'            <dependency>',
				'                <groupId>com.example</groupId>',
				'                <artifactId>managed-lib</artifactId>',
				'                <version>1.0.0</version>',
				'            </dependency>',
				'        </dependencies>',
				'    </dependencyManagement>',
				'    <dependencies>',
				'        <dependency>',
				'            <groupId>com.example</groupId>',
				'            <artifactId>managed-lib</artifactId>',
				'        </dependency>',
				'    </dependencies>',
				'</project>',
			].join('\n');

			// When
			const result = updateMavenVersions(pom, [
				{ groupId: 'com.example', artifactId: 'managed-lib', newVersion: '2.0.0' },
			]);

			// Then
			expect(result.applied).to.have.lengthOf(1);
			expect(result.content).to.include('<version>2.0.0</version>');
			expect(result.content).not.to.include('<version>1.0.0</version>');
		});
	});
});
