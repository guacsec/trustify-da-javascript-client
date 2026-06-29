import { expect } from 'chai'

import dockerfileProvider, { parseFromImage } from '../../src/providers/oci_dockerfile.js'

suite('testing the Dockerfile/Containerfile data provider', () => {

	suite('isSupported', () => {
		/** Verifies that isSupported returns true for Dockerfile and Containerfile, false for others. */
		['Dockerfile', 'Containerfile'].forEach(name => {
			test(`returns true for ${name}`, () => {
				expect(dockerfileProvider.isSupported(name)).to.equal(true)
			})
		});

		['package.json', 'go.mod', 'Cargo.toml', 'dockerfile', 'containerfile', 'Dockerfile.dev'].forEach(name => {
			test(`returns false for ${name}`, () => {
				expect(dockerfileProvider.isSupported(name)).to.equal(false)
			})
		})
	})

	suite('validateLockFile', () => {
		/** Verifies that validateLockFile always returns true since Dockerfiles have no lock file. */
		test('always returns true', () => {
			expect(dockerfileProvider.validateLockFile()).to.equal(true)
		})
	})

	suite('readLicenseFromManifest', () => {
		/** Verifies that readLicenseFromManifest returns null since Dockerfiles have no license info. */
		test('returns null', () => {
			expect(dockerfileProvider.readLicenseFromManifest()).to.equal(null)
		})
	})

	suite('packageManagerName', () => {
		/** Verifies that packageManagerName returns oci. */
		test('returns oci', () => {
			expect(dockerfileProvider.packageManagerName()).to.equal('oci')
		})
	})

	suite('parseFromImage', () => {
		/** Verifies that a single FROM line extracts the correct image reference. */
		test('extracts image from single-stage Dockerfile', () => {
			const content = 'FROM node:18\nRUN npm install\n'
			expect(parseFromImage(content)).to.equal('node:18')
		})

		/** Verifies that the last FROM line is used in multi-stage Dockerfiles. */
		test('uses last FROM in multi-stage Dockerfile', () => {
			const content = [
				'FROM node:18 AS builder',
				'RUN npm run build',
				'',
				'FROM nginx:alpine',
				'COPY --from=builder /app/dist /usr/share/nginx/html',
			].join('\n')
			expect(parseFromImage(content)).to.equal('nginx:alpine')
		})

		/** Verifies that a single --platform flag is skipped when parsing FROM lines. */
		test('handles --platform flag', () => {
			const content = 'FROM --platform=linux/amd64 ubuntu:22.04\n'
			expect(parseFromImage(content)).to.equal('ubuntu:22.04')
		})

		/** Verifies that multiple flags before the image reference are all skipped. */
		test('handles multiple flags before image', () => {
			const content = 'FROM --platform=linux/amd64 --some-flag=value ubuntu:22.04 AS base\n'
			expect(parseFromImage(content)).to.equal('ubuntu:22.04')
		})

		/** Verifies that image references with digests are parsed correctly. */
		test('handles image with digest', () => {
			const content = 'FROM httpd@sha256:abc123\n'
			expect(parseFromImage(content)).to.equal('httpd@sha256:abc123')
		})

		/** Verifies that an error is thrown when no FROM line is present. */
		test('throws when no FROM line found', () => {
			const content = 'RUN echo hello\n'
			expect(() => parseFromImage(content)).to.throw('No FROM line found in Dockerfile')
		})

		/** Verifies that FROM line parsing is case-insensitive. */
		test('handles case-insensitive FROM keyword', () => {
			const content = 'from alpine:3.18\n'
			expect(parseFromImage(content)).to.equal('alpine:3.18')
		})

		/** Verifies that comment lines and blank lines are ignored. */
		test('ignores comments and blank lines', () => {
			const content = [
				'# This is a comment',
				'',
				'FROM registry.example.com/myapp:latest',
			].join('\n')
			expect(parseFromImage(content)).to.equal('registry.example.com/myapp:latest')
		})
	})
})
