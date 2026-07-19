import { expect } from 'chai'
import esmock from 'esmock'

import dockerfileProvider, { parseAllFromImages } from '../../src/providers/oci_dockerfile.js'

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

	suite('parseAllFromImages', () => {
		/** Verifies that a single FROM line returns a single-element array. */
		test('returns single-element array for single-FROM Dockerfile', async () => {
			const content = 'FROM node:18\nRUN npm install\n'
			const result = await parseAllFromImages(content)
			expect(result).to.deep.equal(['node:18'])
		})

		/** Verifies that all FROM lines are returned from a multi-stage Dockerfile. */
		test('returns all image refs from multi-stage Dockerfile', async () => {
			const content = [
				'FROM node:18 AS builder',
				'RUN npm run build',
				'',
				'FROM nginx:alpine',
				'COPY --from=builder /app/dist /usr/share/nginx/html',
			].join('\n')
			const result = await parseAllFromImages(content)
			expect(result).to.deep.equal(['node:18', 'nginx:alpine'])
		})

		/** Verifies that FROM lines with ARG substitution are resolved using declared defaults. */
		test('resolves ARG substitution in FROM lines using declared defaults', async () => {
			const content = [
				'ARG BASE_IMAGE=ubuntu:22.04',
				'FROM ${BASE_IMAGE} AS base',
				'RUN echo hello',
				'',
				'FROM alpine:3.18',
				'COPY --from=base /app /app',
			].join('\n')
			const result = await parseAllFromImages(content)
			expect(result).to.deep.equal(['ubuntu:22.04', 'alpine:3.18'])
		})

		/** Verifies that FROM lines with unresolvable ARGs (no default) are skipped. */
		test('skips FROM lines with ARG without default value', async () => {
			const content = [
				'ARG BASE_IMAGE',
				'FROM ${BASE_IMAGE} AS base',
				'RUN echo hello',
				'',
				'FROM alpine:3.18',
				'COPY --from=base /app /app',
			].join('\n')
			const result = await parseAllFromImages(content)
			expect(result).to.deep.equal(['alpine:3.18'])
		})

		/** Verifies that a single --platform flag is skipped when parsing FROM lines. */
		test('handles --platform flag', async () => {
			const content = 'FROM --platform=linux/amd64 ubuntu:22.04\n'
			const result = await parseAllFromImages(content)
			expect(result).to.deep.equal(['ubuntu:22.04'])
		})

		/** Verifies that multiple flags before the image reference are all skipped. */
		test('handles multiple flags before image', async () => {
			const content = 'FROM --platform=linux/amd64 --some-flag=value ubuntu:22.04 AS base\n'
			const result = await parseAllFromImages(content)
			expect(result).to.deep.equal(['ubuntu:22.04'])
		})

		/** Verifies that image references with digests are parsed correctly. */
		test('handles image with digest', async () => {
			const content = 'FROM httpd@sha256:abc123\n'
			const result = await parseAllFromImages(content)
			expect(result).to.deep.equal(['httpd@sha256:abc123'])
		})

		/** Verifies that ARG with default resolves successfully in a single FROM. */
		test('resolves single FROM with ARG default', async () => {
			const content = 'ARG BASE_IMAGE=ubuntu:22.04\nFROM ${BASE_IMAGE}\n'
			const result = await parseAllFromImages(content)
			expect(result).to.deep.equal(['ubuntu:22.04'])
		})

		/** Verifies that an error is thrown when all FROM lines use unresolvable ARG substitution. */
		test('throws when all FROM lines use ARG without defaults', async () => {
			const content = 'ARG BASE_IMAGE\nFROM ${BASE_IMAGE}\n'
			try {
				await parseAllFromImages(content)
				expect.fail('should have thrown')
			} catch (e) {
				expect(e.message).to.include('Dockerfile uses ARG substitution in all FROM lines')
			}
		})

		/** Verifies that an error is thrown when no FROM line is present. */
		test('throws when no FROM line found', async () => {
			const content = 'RUN echo hello\n'
			try {
				await parseAllFromImages(content)
				expect.fail('should have thrown')
			} catch (e) {
				expect(e.message).to.include('No FROM line found in Dockerfile')
			}
		})

		/** Verifies that FROM line parsing is case-insensitive. */
		test('handles case-insensitive FROM keyword', async () => {
			const content = 'from alpine:3.18\n'
			const result = await parseAllFromImages(content)
			expect(result).to.deep.equal(['alpine:3.18'])
		})

		/** Verifies that ARG with double-quoted default is resolved correctly. */
		test('resolves ARG with double-quoted default', async () => {
			const content = 'ARG BASE_IMAGE="ubuntu:22.04"\nFROM ${BASE_IMAGE}\n'
			const result = await parseAllFromImages(content)
			expect(result).to.deep.equal(['ubuntu:22.04'])
		})

		/** Verifies that ARG with single-quoted default is resolved correctly. */
		test('resolves ARG with single-quoted default', async () => {
			const content = "ARG BASE_IMAGE='alpine:3.18'\nFROM ${BASE_IMAGE}\n"
			const result = await parseAllFromImages(content)
			expect(result).to.deep.equal(['alpine:3.18'])
		})

		/** Verifies that comment lines and blank lines are ignored. */
		test('ignores comments and blank lines', async () => {
			const content = [
				'# This is a comment',
				'',
				'FROM registry.example.com/myapp:latest',
			].join('\n')
			const result = await parseAllFromImages(content)
			expect(result).to.deep.equal(['registry.example.com/myapp:latest'])
		})

		/** Verifies that a three-stage Dockerfile returns all three image refs. */
		test('returns all images from three-stage Dockerfile', async () => {
			const content = [
				'FROM golang:1.21 AS build',
				'RUN go build -o app',
				'',
				'FROM node:20 AS frontend',
				'RUN npm run build',
				'',
				'FROM alpine:3.19',
				'COPY --from=build /app /app',
				'COPY --from=frontend /dist /dist',
			].join('\n')
			const result = await parseAllFromImages(content)
			expect(result).to.deep.equal(['golang:1.21', 'node:20', 'alpine:3.19'])
		})
	})

	suite('provideStack / provideComponent batch output', () => {
		/** Verifies that provideStack returns batch format with batch: true flag. */
		test('provideStack returns batch format with batch flag', async () => {
			// Given a mock Dockerfile with two FROM stages
			const fakeSbom1 = { metadata: { component: { purl: 'pkg:oci/node@18' } } }
			const fakeSbom2 = { metadata: { component: { purl: 'pkg:oci/nginx@alpine' } } }
			let sbomCallIndex = 0

			const mockedProvider = await esmock('../../src/providers/oci_dockerfile.js', {
				'node:fs': {
					readFileSync: () => 'FROM node:18 AS builder\nFROM nginx:alpine\n'
				},
				'../../src/oci_image/utils.js': {
					parseImageRef: (image) => ({
						getPackageURL: () => ({ toString: () => `pkg:oci/${image}` })
					}),
					generateImageSBOM: () => {
						return sbomCallIndex++ === 0 ? fakeSbom1 : fakeSbom2
					}
				}
			})

			// When calling provideStack
			const result = await mockedProvider.default.provideStack('/fake/Dockerfile')

			// Then the result should have batch format
			expect(result.ecosystem).to.equal('oci')
			expect(result.contentType).to.equal('application/vnd.cyclonedx+json')
			expect(result.batch).to.equal(true)

			const parsed = JSON.parse(result.content)
			expect(Object.keys(parsed)).to.have.lengthOf(2)
			expect(parsed['pkg:oci/node:18']).to.deep.equal(fakeSbom1)
			expect(parsed['pkg:oci/nginx:alpine']).to.deep.equal(fakeSbom2)
		})

		/** Verifies that provideComponent returns batch format with batch: true flag. */
		test('provideComponent returns batch format with batch flag', async () => {
			// Given a mock Dockerfile with a single FROM stage
			const fakeSbom = { metadata: { component: { purl: 'pkg:oci/alpine@3.19' } } }

			const mockedProvider = await esmock('../../src/providers/oci_dockerfile.js', {
				'node:fs': {
					readFileSync: () => 'FROM alpine:3.19\n'
				},
				'../../src/oci_image/utils.js': {
					parseImageRef: (image) => ({
						getPackageURL: () => ({ toString: () => `pkg:oci/${image}` })
					}),
					generateImageSBOM: () => fakeSbom
				}
			})

			// When calling provideComponent
			const result = await mockedProvider.default.provideComponent('/fake/Dockerfile')

			// Then the result should have batch format with one entry
			expect(result.ecosystem).to.equal('oci')
			expect(result.contentType).to.equal('application/vnd.cyclonedx+json')
			expect(result.batch).to.equal(true)

			const parsed = JSON.parse(result.content)
			expect(Object.keys(parsed)).to.have.lengthOf(1)
			expect(parsed['pkg:oci/alpine:3.19']).to.deep.equal(fakeSbom)
		})

		/** Verifies that batch output contains correct purl keys mapped to SBOM objects. */
		test('batch output maps purl keys to correct SBOM objects', async () => {
			// Given a mock Dockerfile with three FROM stages
			const sboms = {
				'golang:1.21': { metadata: { component: { name: 'golang' } } },
				'node:20': { metadata: { component: { name: 'node' } } },
				'alpine:3.19': { metadata: { component: { name: 'alpine' } } }
			}

			const mockedProvider = await esmock('../../src/providers/oci_dockerfile.js', {
				'node:fs': {
					readFileSync: () => 'FROM golang:1.21 AS build\nFROM node:20 AS frontend\nFROM alpine:3.19\n'
				},
				'../../src/oci_image/utils.js': {
					parseImageRef: (image) => ({
						getPackageURL: () => ({ toString: () => `pkg:oci/${image}` })
					}),
					generateImageSBOM: (imageRef) => {
						const purl = imageRef.getPackageURL().toString()
						const image = purl.replace('pkg:oci/', '')
						return sboms[image]
					}
				}
			})

			// When calling provideStack
			const result = await mockedProvider.default.provideStack('/fake/Dockerfile')

			// Then each purl key should map to the correct SBOM
			const parsed = JSON.parse(result.content)
			expect(Object.keys(parsed)).to.have.lengthOf(3)
			expect(parsed['pkg:oci/golang:1.21'].metadata.component.name).to.equal('golang')
			expect(parsed['pkg:oci/node:20'].metadata.component.name).to.equal('node')
			expect(parsed['pkg:oci/alpine:3.19'].metadata.component.name).to.equal('alpine')
		})
	})
})
