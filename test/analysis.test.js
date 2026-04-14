import fs from 'node:fs'
import { expect } from 'chai'
import { HttpsProxyAgent } from 'https-proxy-agent'
import { afterEach } from 'mocha'
import { http, HttpResponse } from 'msw'
import { setupServer } from 'msw/node'
import { stub } from 'sinon'

import analysis from '../src/analysis.js'
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
})
