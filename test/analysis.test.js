import fs from 'node:fs'

import { expect } from 'chai'
import { HttpsProxyAgent } from 'https-proxy-agent'
import { afterEach } from 'mocha'
import { http, HttpResponse } from 'msw'
import { setupServer } from 'msw/node'
import { stub, useFakeTimers } from 'sinon'

import analysis from '../src/analysis.js'
import pythonPip from '../src/providers/python_pip.js'
import { addProxyAgent } from '../src/tools.js'

// utility function creating a dummy server, intercepting a handler,
// running a test, and shutting the server down
function interceptAndRun(handler, test) {
	return async () => {
		let server = setupServer(handler)
		server.listen()

		return Promise.resolve(test(server))
			.finally(() => {
				server.resetHandlers()
				server.close()
			});
	};
}

function determineResponse({ request }) {
	const token = request.headers.get("trust-da-token")
	if (token == null) {
		return new HttpResponse(null, { status: 400 })
	} else if (token === "good-dummy-token") {
		return new HttpResponse(null, { status: 200 })
	} else {
		return new HttpResponse(null, { status: 401 })
	}
}

suite('testing the analysis module for sending api requests', () => {
	let backendUrl = 'http://url.lru' // dummy backend url will be used for fake server
	// fake provided data, in prod will be provided by the provider and used for creating requests
	let fakeProvided = {
		ecosystem: 'dummy-ecosystem',
		content: 'dummy-content',
		contentType: 'dummy-content-type'
	};

	suite('testing the requestComponent function', () => {
		let fakeManifest = 'fake-component-manifest.typ'
		let componentProvideStub = stub()
		componentProvideStub.withArgs(fakeManifest).returns(fakeProvided)
		let fakeProvider = {
			provideComponent: componentProvideStub,
			provideStack: () => { },
			isSupported: () => { }
		}

		setup(() => {
			fs.writeFileSync(fakeManifest, 'dummy-content')
		})

		teardown(() => {
			if (fs.existsSync(fakeManifest)) {
				fs.unlinkSync(fakeManifest)
			}
		})

		test('invoking the requestComponent should return a json report', interceptAndRun(
			http.post(`${backendUrl}/api/v5/analysis`, ({ request }) => {
				if (fakeProvided.contentType === request.headers.get('content-type')) {
					return HttpResponse.json({ dummy: 'response' })
				}
				return new HttpResponse(null, { status: 400 })
			}),
			async () => {
				let res = await analysis.requestComponent(fakeProvider, fakeManifest, backendUrl)
				expect(res.dummy).to.equal('response')
			}
		))

		test('licenseCheck option overrides the environment variable', interceptAndRun(
			http.post(`${backendUrl}/api/v5/analysis`, () => HttpResponse.json({ dummy: 'response' })),
			async () => {
				process.env.TRUSTIFY_DA_LICENSE_CHECK = 'false'
				try {
					const res = await analysis.requestComponent(
						fakeProvider, fakeManifest, backendUrl, { licenseCheck: true }
					)
					expect(res).to.have.property('licenseSummary')
				} finally {
					delete process.env.TRUSTIFY_DA_LICENSE_CHECK
				}
			}
		))
	})

	suite('testing the requestStack function', () => {
		let fakeManifest = 'fake-file.typ'
		let stackProviderStub = stub()
		stackProviderStub.withArgs(fakeManifest).returns(fakeProvided)
		let fakeProvider = {
			provideComponent: () => { },
			provideStack: stackProviderStub,
			isSupported: () => { }
		}

		setup(() => {
			fs.writeFileSync(fakeManifest, 'dummy-content')
		})

		teardown(() => {
			if (fs.existsSync(fakeManifest)) {
				fs.unlinkSync(fakeManifest)
			}
		})

		test('invoking the requestStack for html should return a string report', interceptAndRun(
			http.post(`${backendUrl}/api/v5/analysis`, ({ request }) => {
				if (fakeProvided.contentType === request.headers.get('content-type')) {
					return new HttpResponse('<html lang="en">html-content</html>')
				}
				return new HttpResponse(null, { status: 400 })
			}),
			async () => {
				let res = await analysis.requestStack(fakeProvider, fakeManifest, backendUrl, true)
				expect(res).to.equal('<html lang="en">html-content</html>')
			}
		))

		test('invoking the requestStack for non-html should return a json report', interceptAndRun(
			http.post(`${backendUrl}/api/v5/analysis`, ({ request }) => {
				if (fakeProvided.contentType === request.headers.get('content-type')) {
					return HttpResponse.json({ dummy: 'response' })
				}
				return new HttpResponse(null, { status: 400 })
			}),
			async () => {
				let res = await analysis.requestStack(fakeProvider, fakeManifest, backendUrl)
				expect(res).to.deep.equal({ dummy: 'response' })
			}
		))
	})
	suite('testing the validateToken function', () => {

		test('invoking validateToken function with good token', interceptAndRun(
			http.get(`${backendUrl}/api/v5/token`, determineResponse),
			async () => {
				let options = {
					'TRUSTIFY_DA_TOKEN': 'good-dummy-token'
				}
				let res = await analysis.validateToken(backendUrl, options)
				expect(res).to.equal(200)
			}
		))
		test('invoking validateToken function with bad token', interceptAndRun(
			http.get(`${backendUrl}/api/v5/token`, determineResponse),
			async () => {
				let options = {
					'TRUSTIFY_DA_TOKEN': 'bad-dummy-token'
				}
				let res = await analysis.validateToken(backendUrl, options)
				expect(res).to.equal(401)
			}
		))
		test('invoking validateToken function without token', interceptAndRun(
			http.get(`${backendUrl}/api/v5/token`, determineResponse),
			async () => {
				let options = {
				}
				let res = await analysis.validateToken(backendUrl, options)
				expect(res).to.equal(400)
			}
		))

	})

	suite('verify environment variables to token headers mechanism', () => {
		let fakeManifest = 'fake-file.typ'
		let stackProviderStub = stub()
		stackProviderStub.withArgs(fakeManifest).returns(fakeProvided)
		let fakeProvider = {
			provideComponent: () => { },
			provideStack: stackProviderStub,
			isSupported: () => { }
		};

		setup(() => {
			fs.writeFileSync(fakeManifest, 'dummy-content')
		})

		teardown(() => {
			if (fs.existsSync(fakeManifest)) {
				fs.unlinkSync(fakeManifest)
			}
			delete process.env['TRUSTIFY_DA_TOKEN']
		})

		test('when the relevant token environment variables are set, verify corresponding headers are included', interceptAndRun(
			http.post(`${backendUrl}/api/v5/analysis`, ({ request }) => {
				if ('dummy-token' === request.headers.get('trust-da-token')) {
					return HttpResponse.json({ ok: 'ok' })
				}
				return new HttpResponse(null, { status: 400 })
			}),
			async () => {
				process.env['TRUSTIFY_DA_TOKEN'] = 'dummy-token'
				let res = await analysis.requestStack(fakeProvider, fakeManifest, backendUrl)
				expect(res).to.deep.equal({ ok: 'ok' })
			}
		))

		test('when the relevant token environment variables are not set, verify no corresponding headers are included', interceptAndRun(
			http.post(`${backendUrl}/api/v5/analysis`, ({ request }) => {
				if (!request.headers.get('trust-da-token')) {
					return HttpResponse.json({ ok: 'ok' })
				}
				return new HttpResponse(null, { status: 400 })
			}),
			async () => {
				let res = await analysis.requestStack(fakeProvider, fakeManifest, backendUrl)
				expect(res).to.deep.equal({ ok: 'ok' })
			}
		))
	})

	suite('appendAnalysisQueryParams — URL construction with providers and sources', () => {
		/** Verifies that providers param is appended when set via opts. */
		test('appends providers query param from opts', () => {
			const url = new URL('http://example.com/api/v5/analysis')
			analysis.appendAnalysisQueryParams(url, { TRUSTIFY_DA_PROVIDERS: 'redhat,lightwell' })
			expect(url.searchParams.get('providers')).to.equal('redhat,lightwell')
		})

		/** Verifies that sources param is appended when set via opts. */
		test('appends sources query param from opts', () => {
			const url = new URL('http://example.com/api/v5/analysis')
			analysis.appendAnalysisQueryParams(url, { TRUSTIFY_DA_SOURCES: 'osv' })
			expect(url.searchParams.get('sources')).to.equal('osv')
		})

		/** Verifies that both providers and sources are appended together. */
		test('appends both providers and sources when both are set', () => {
			const url = new URL('http://example.com/api/v5/analysis')
			analysis.appendAnalysisQueryParams(url, {
				TRUSTIFY_DA_PROVIDERS: 'redhat',
				TRUSTIFY_DA_SOURCES: 'osv,nvd'
			})
			expect(url.searchParams.get('providers')).to.equal('redhat')
			expect(url.searchParams.get('sources')).to.equal('osv,nvd')
		})

		/** Verifies that no providers or sources params are added when neither is set. */
		test('does not append providers or sources when neither is set', () => {
			const url = new URL('http://example.com/api/v5/analysis')
			analysis.appendAnalysisQueryParams(url, {})
			expect(url.searchParams.has('providers')).to.equal(false)
			expect(url.searchParams.has('sources')).to.equal(false)
		})

		/** Verifies that environment variables are respected as fallback for providers. */
		test('reads providers from environment variable when opts is empty', () => {
			process.env['TRUSTIFY_DA_PROVIDERS'] = 'trustify'
			try {
				const url = new URL('http://example.com/api/v5/analysis')
				analysis.appendAnalysisQueryParams(url, {})
				expect(url.searchParams.get('providers')).to.equal('trustify')
			} finally {
				delete process.env['TRUSTIFY_DA_PROVIDERS']
			}
		})

		/** Verifies that environment variables are respected as fallback for sources. */
		test('reads sources from environment variable when opts is empty', () => {
			process.env['TRUSTIFY_DA_SOURCES'] = 'osv'
			try {
				const url = new URL('http://example.com/api/v5/analysis')
				analysis.appendAnalysisQueryParams(url, {})
				expect(url.searchParams.get('sources')).to.equal('osv')
			} finally {
				delete process.env['TRUSTIFY_DA_SOURCES']
			}
		})

		test('opts override environment variables', () => {
			process.env.TRUSTIFY_DA_PROVIDERS = 'env-provider'
			process.env.TRUSTIFY_DA_SOURCES = 'env-source'
			process.env.TRUSTIFY_DA_RECOMMEND = 'false'
			try {
				const url = new URL('http://example.com/api/v5/analysis')
				analysis.appendAnalysisQueryParams(url, {
					TRUSTIFY_DA_PROVIDERS: 'opts-provider',
					TRUSTIFY_DA_SOURCES: 'opts-source',
					TRUSTIFY_DA_RECOMMEND: 'true',
				})
				expect(url.searchParams.get('providers')).to.equal('opts-provider')
				expect(url.searchParams.get('sources')).to.equal('opts-source')
				expect(url.searchParams.has('recommend')).to.equal(false)
			} finally {
				delete process.env.TRUSTIFY_DA_PROVIDERS
				delete process.env.TRUSTIFY_DA_SOURCES
				delete process.env.TRUSTIFY_DA_RECOMMEND
			}
		})

		/** Verifies that recommend=false is still appended alongside providers/sources. */
		test('appends recommend=false alongside providers and sources', () => {
			const url = new URL('http://example.com/api/v5/analysis')
			analysis.appendAnalysisQueryParams(url, {
				TRUSTIFY_DA_RECOMMEND: 'false',
				TRUSTIFY_DA_PROVIDERS: 'redhat',
				TRUSTIFY_DA_SOURCES: 'osv'
			})
			expect(url.searchParams.get('recommend')).to.equal('false')
			expect(url.searchParams.get('providers')).to.equal('redhat')
			expect(url.searchParams.get('sources')).to.equal('osv')
		})
	})

	suite('verify providers and sources are forwarded in HTTP requests', () => {
		let fakeManifest = 'fake-file-providers.typ'
		let stackProviderStub = stub()
		let fakeProvided = {
			ecosystem: 'dummy-ecosystem',
			content: 'dummy-content',
			contentType: 'dummy-content-type'
		}
		stackProviderStub.withArgs(fakeManifest).returns(fakeProvided)
		let fakeProvider = {
			provideComponent: () => { },
			provideStack: stackProviderStub,
			isSupported: () => { }
		}

		setup(() => {
			fs.writeFileSync(fakeManifest, 'dummy-content')
		})

		teardown(() => {
			if (fs.existsSync(fakeManifest)) {
				fs.unlinkSync(fakeManifest)
			}
		})

		/** Verifies that providers query param reaches the backend URL during stack analysis. */
		test('requestStack sends providers query param to backend', interceptAndRun(
			http.post(`${backendUrl}/api/v5/analysis`, ({ request }) => {
				const url = new URL(request.url)
				if (url.searchParams.get('providers') === 'redhat,lightwell') {
					return HttpResponse.json({ filtered: true })
				}
				return new HttpResponse(null, { status: 400 })
			}),
			async () => {
				let res = await analysis.requestStack(
					fakeProvider, fakeManifest, backendUrl, false,
					{ TRUSTIFY_DA_PROVIDERS: 'redhat,lightwell' }
				)
				expect(res).to.deep.equal({ filtered: true })
			}
		))

		/** Verifies that sources query param reaches the backend URL during stack analysis. */
		test('requestStack sends sources query param to backend', interceptAndRun(
			http.post(`${backendUrl}/api/v5/analysis`, ({ request }) => {
				const url = new URL(request.url)
				if (url.searchParams.get('sources') === 'osv') {
					return HttpResponse.json({ sourceFiltered: true })
				}
				return new HttpResponse(null, { status: 400 })
			}),
			async () => {
				let res = await analysis.requestStack(
					fakeProvider, fakeManifest, backendUrl, false,
					{ TRUSTIFY_DA_SOURCES: 'osv' }
				)
				expect(res).to.deep.equal({ sourceFiltered: true })
			}
		))
	})

	suite('addProxyAgent', () => {
		afterEach(() => {
			delete process.env['TRUSTIFY_DA_PROXY_URL']
		})

		test('should set HttpsProxyAgent when proxy URL is provided via options', () => {
			const options = { method: 'POST' }
			const result = addProxyAgent(options, { 'TRUSTIFY_DA_PROXY_URL': 'http://proxy.example.com:8080' })
			expect(result.agent).to.be.instanceOf(HttpsProxyAgent)
			expect(result.agent.proxy.href).to.equal('http://proxy.example.com:8080/')
		})

		test('should set HttpsProxyAgent for HTTPS proxy URL', () => {
			const options = { method: 'POST' }
			const result = addProxyAgent(options, { 'TRUSTIFY_DA_PROXY_URL': 'https://proxy.example.com:8443' })
			expect(result.agent).to.be.instanceOf(HttpsProxyAgent)
			expect(result.agent.proxy.href).to.equal('https://proxy.example.com:8443/')
		})

		test('should set HttpsProxyAgent when proxy URL is provided via environment variable', () => {
			process.env['TRUSTIFY_DA_PROXY_URL'] = 'http://proxy.example.com:8080'
			const options = { method: 'POST' }
			const result = addProxyAgent(options, {})
			expect(result.agent).to.be.instanceOf(HttpsProxyAgent)
			expect(result.agent.proxy.href).to.equal('http://proxy.example.com:8080/')
		})

		test('should not set agent when no proxy is configured', () => {
			const options = { method: 'POST' }
			const result = addProxyAgent(options, {})
			expect(result.agent).to.be.undefined
		})
	})

	suite('verify proxy configuration', () => {
		let fakeManifest = 'fake-file.typ'
		let stackProviderStub = stub()
		stackProviderStub.withArgs(fakeManifest).returns(fakeProvided)
		let fakeProvider = {
			provideComponent: () => { },
			provideStack: stackProviderStub,
			isSupported: () => { }
		};

		setup(() => {
			fs.writeFileSync(fakeManifest, 'dummy-content')
		})

		teardown(() => {
			if (fs.existsSync(fakeManifest)) {
				fs.unlinkSync(fakeManifest)
			}
			delete process.env['TRUSTIFY_DA_PROXY_URL']
		})

		test('when HTTP proxy is configured, verify request succeeds', interceptAndRun(
			http.post(`${backendUrl}/api/v5/analysis`, () => {
				return HttpResponse.json({ ok: 'ok' })
			}),
			async () => {
				const options = {
					'TRUSTIFY_DA_PROXY_URL': 'http://proxy.example.com:8080'
				}
				let res = await analysis.requestStack(fakeProvider, fakeManifest, backendUrl, false, options)
				expect(res).to.deep.equal({ ok: 'ok' })
			}
		))

		test('when HTTPS proxy is configured, verify request succeeds', interceptAndRun(
			http.post(`${backendUrl}/api/v5/analysis`, () => {
				return HttpResponse.json({ ok: 'ok' })
			}),
			async () => {
				const options = {
					'TRUSTIFY_DA_PROXY_URL': 'https://proxy.example.com:8080'
				}
				let res = await analysis.requestStack(fakeProvider, fakeManifest, backendUrl, false, options)
				expect(res).to.deep.equal({ ok: 'ok' })
			}
		))

		test('when proxy is configured via environment variable, verify request succeeds', interceptAndRun(
			http.post(`${backendUrl}/api/v5/analysis`, () => {
				return HttpResponse.json({ ok: 'ok' })
			}),
			async () => {
				process.env['TRUSTIFY_DA_PROXY_URL'] = 'http://proxy.example.com:8080'
				let res = await analysis.requestStack(fakeProvider, fakeManifest, backendUrl)
				expect(res).to.deep.equal({ ok: 'ok' })
			}
		))

		test('when no proxy is configured, verify request succeeds', interceptAndRun(
			http.post(`${backendUrl}/api/v5/analysis`, () => {
				return HttpResponse.json({ ok: 'ok' })
			}),
			async () => {
				let res = await analysis.requestStack(fakeProvider, fakeManifest, backendUrl)
				expect(res).to.deep.equal({ ok: 'ok' })
			}
		))
	})

	suite('audit metadata preserves decoded requirements manifests', () => {
		const goldenSbomDir = 'test/providers/tst_manifests/pip/pip_requirements_txt_utf16le'
		const utf16leManifest = `${goldenSbomDir}/requirements.txt`
		// Plain text of the committed UTF-16LE fixture, used as the expected decoded audit payload.
		const requirementsText = 'blinker==1.9.0\r\ncertifi==2026.10.23\r\nsix==1.16.0 # exhortignore\r\n'
		const expectedAuditContent = Buffer.from(requirementsText).toString('base64')
		const pipFreezeOutput = 'blinker==1.9.0\ncertifi==2026.10.23\nsix==1.16.0\n'
		const pipShowOutput =
			'Name: blinker\nVersion: 1.9.0\nSummary: Fast, simple object-to-object and broadcast signaling\nRequires: \nRequired-by: ' +
			'\n---\n' +
			'Name: certifi\nVersion: 2026.10.23\nSummary: Python package for providing Mozilla\'s CA Bundle.\nRequires: \nRequired-by: ' +
			'\n---\n' +
			'Name: six\nVersion: 1.16.0\nSummary: Python 2 and 3 compatibility utilities\nRequires: \nRequired-by: '
		let clock

		suiteSetup(() => {
			// Only fake Date so SBOM timestamps are deterministic; fetch/MSW rely on real timers.
			clock = useFakeTimers({ now: new Date('2023-10-01T00:00:00.000Z'), toFake: ['Date'] })
		})

		suiteTeardown(() => {
			clock.restore()
		})

		/**
		 * Build the expected audited SBOM from a committed golden, adding the audit
		 * properties the public analysis path is responsible for submitting.
		 * @param {string} goldenFile - golden SBOM file name
		 * @returns {object} expected SBOM including audit metadata
		 */
		function expectedSbomWithAudit(goldenFile) {
			const sbom = JSON.parse(fs.readFileSync(`${goldenSbomDir}/${goldenFile}`).toString())
			sbom.metadata.properties = [
				{ name: 'rhda:manifest:content', value: expectedAuditContent },
				{ name: 'rhda:manifest:filename', value: 'requirements.txt' }
			]
			return sbom
		}

		/**
		 * Run a provider-backed request with a deterministic pip environment, so the
		 * assertion focuses on audit decoding rather than on the host pip packages.
		 * @param {Function} run - request to execute
		 * @returns {Promise<*>} the value returned by `run`
		 */
		async function withPipEnvironment(run) {
			process.env['TRUSTIFY_DA_PIP_FREEZE'] = Buffer.from(pipFreezeOutput).toString('base64')
			process.env['TRUSTIFY_DA_PIP_SHOW'] = Buffer.from(pipShowOutput).toString('base64')
			try {
				return await run()
			} finally {
				delete process.env['TRUSTIFY_DA_PIP_FREEZE']
				delete process.env['TRUSTIFY_DA_PIP_SHOW']
			}
		}

		let submittedSbom

		/** Verifies requestStack submits decoded UTF-16LE requirements text in a complete audited SBOM. */
		test('requestStack submits decoded UTF-16LE requirements audit metadata', interceptAndRun(
			http.post(`${backendUrl}/api/v5/analysis`, async ({ request }) => {
				submittedSbom = await request.json()
				return HttpResponse.json({ dummy: 'response' })
			}),
			async () => {
				// Given the committed UTF-16LE fixture
				// When stack analysis runs through the public request path
				await withPipEnvironment(() => analysis.requestStack(pythonPip, utf16leManifest, backendUrl))

				// Then the submitted SBOM equals the golden including exact audit metadata
				expect(submittedSbom).to.deep.equal(expectedSbomWithAudit('expected_stack_sbom.json'))
				const auditProperty = submittedSbom.metadata.properties
					.find(property => property.name === 'rhda:manifest:content')
				expect(Buffer.from(auditProperty.value, 'base64').toString('utf8')).to.equal(requirementsText)
			}
		)).timeout(10000)

		/** Verifies component requests without manifest-type still omit audit metadata. */
		test('requestComponent without manifest-type omits audit metadata', interceptAndRun(
			http.post(`${backendUrl}/api/v5/analysis`, async ({ request }) => {
				submittedSbom = await request.json()
				return HttpResponse.json({ dummy: 'response' })
			}),
			async () => {
				// Given the UTF-16LE fixture and no manifest-type option
				// When component analysis runs
				await withPipEnvironment(() => analysis.requestComponent(
					pythonPip, utf16leManifest, backendUrl, { licenseCheck: false }
				))

				// Then the submitted SBOM matches the unaudited golden with no metadata.properties
				expect(submittedSbom).to.deep.equal(
					JSON.parse(fs.readFileSync(`${goldenSbomDir}/expected_component_sbom.json`).toString())
				)
			}
		)).timeout(10000)

		/** Verifies non-requirements manifests keep the existing raw audit bytes. */
		test('requestStack leaves non-requirements audit bytes raw', interceptAndRun(
			http.post(`${backendUrl}/api/v5/analysis`, () => HttpResponse.json({ dummy: 'response' })),
			async () => {
				// Given a non-requirements manifest whose bytes start with a UTF-8 BOM
				const manifest = 'fake-audit-manifest.typ'
				const rawBytes = Buffer.concat([Buffer.from([0xEF, 0xBB, 0xBF]), Buffer.from('dummy-content', 'utf8')])
				fs.writeFileSync(manifest, rawBytes)
				let recordedSourceManifest
				const provider = {
					provideStack: (manifestPath, opts) => {
						recordedSourceManifest = opts['source-manifest']
						return { ecosystem: 'dummy-ecosystem', content: 'dummy-content', contentType: 'dummy-content-type' }
					},
					provideComponent: () => { },
					isSupported: () => { }
				}

				try {
					// When stack analysis runs
					await analysis.requestStack(provider, manifest, backendUrl)

					// Then the audit payload is still the raw file bytes, BOM included
					expect(recordedSourceManifest).to.equal(rawBytes.toString('base64'))
				} finally {
					fs.unlinkSync(manifest)
				}
			}
		))
	})
})
