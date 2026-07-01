import { expect } from 'chai'

import dockerfileProvider, { parseFromImage } from '../../src/providers/oci_dockerfile.js'

suite('testing the Dockerfile/Containerfile data provider', () => {

	suite('isSupported', () => {
		/** Verifies that isSupported returns true for Dockerfile and Containerfile, including suffixed variants. */
		['Dockerfile', 'Containerfile', 'Dockerfile.dev', 'Dockerfile.prod', 'Containerfile.backend'].forEach(name => {
			test(`returns true for ${name}`, () => {
				expect(dockerfileProvider.isSupported(name)).to.equal(true)
			})
		});

		['package.json', 'go.mod', 'Cargo.toml', 'dockerfile', 'containerfile', 'Dockerfilesomething', 'Containerfilesomething', 'Dockerfile.', 'Containerfile.'].forEach(name => {
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
		test('extracts image from single-stage Dockerfile', async () => {
			const content = 'FROM node:18\nRUN npm install\n'
			expect(await parseFromImage(content)).to.equal('node:18')
		})

		/** Verifies that the last FROM line is used in multi-stage Dockerfiles. */
		test('uses last FROM in multi-stage Dockerfile', async () => {
			const content = [
				'FROM node:18 AS builder',
				'RUN npm run build',
				'',
				'FROM nginx:alpine',
				'COPY --from=builder /app/dist /usr/share/nginx/html',
			].join('\n')
			expect(await parseFromImage(content)).to.equal('nginx:alpine')
		})

		/** Verifies that a single --platform flag is skipped when parsing FROM lines. */
		test('handles --platform flag', async () => {
			const content = 'FROM --platform=linux/amd64 ubuntu:22.04\n'
			expect(await parseFromImage(content)).to.equal('ubuntu:22.04')
		})

		/** Verifies that multiple flags before the image reference are all skipped. */
		test('handles multiple flags before image', async () => {
			const content = 'FROM --platform=linux/amd64 --some-flag=value ubuntu:22.04 AS base\n'
			expect(await parseFromImage(content)).to.equal('ubuntu:22.04')
		})

		/** Verifies that image references with digests are parsed correctly. */
		test('handles image with digest', async () => {
			const content = 'FROM httpd@sha256:abc123\n'
			expect(await parseFromImage(content)).to.equal('httpd@sha256:abc123')
		})

		/** Verifies that ARG-substituted FROM targets are rejected with a clear error. */
		test('throws when FROM target uses ARG substitution', async () => {
			const content = 'ARG BASE_IMAGE=ubuntu:22.04\nFROM ${BASE_IMAGE}\n'
			try {
				await parseFromImage(content)
				expect.fail('should have thrown')
			} catch (e) {
				expect(e.message).to.include('Dockerfile uses ARG substitution in FROM line')
			}
		})

		/** Verifies that an error is thrown when no FROM line is present. */
		test('throws when no FROM line found', async () => {
			const content = 'RUN echo hello\n'
			try {
				await parseFromImage(content)
				expect.fail('should have thrown')
			} catch (e) {
				expect(e.message).to.include('No FROM line found in Dockerfile')
			}
		})

		/** Verifies that FROM line parsing is case-insensitive. */
		test('handles case-insensitive FROM keyword', async () => {
			const content = 'from alpine:3.18\n'
			expect(await parseFromImage(content)).to.equal('alpine:3.18')
		})

		/** Verifies that comment lines and blank lines are ignored. */
		test('ignores comments and blank lines', async () => {
			const content = [
				'# This is a comment',
				'',
				'FROM registry.example.com/myapp:latest',
			].join('\n')
			expect(await parseFromImage(content)).to.equal('registry.example.com/myapp:latest')
		})
	})
})
