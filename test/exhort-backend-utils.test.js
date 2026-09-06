import { expect } from 'chai'
import * as chai from 'chai'
import * as sinon from 'sinon'
import sinonChai from 'sinon-chai'

import { selectTrustifyDABackend } from '../src/index.js'
import { getTokenHeaders } from '../src/tools.js';

chai.use(sinonChai)

suite('testing Select Trustify DA Backend function', () => {
	const testUrl = 'https://trustify-da.example.com';
	const testUrl2 = 'https://dev.trustify-da.example.com';

	suiteTeardown(() => {
		delete process.env['TRUSTIFY_DA_BACKEND_URL'];
	});

	test('When TRUSTIFY_DA_BACKEND_URL is set in environment variable, should return that value', () => {
		process.env['TRUSTIFY_DA_BACKEND_URL'] = testUrl;
		let selectedUrl = selectTrustifyDABackend({});
		expect(selectedUrl).to.be.equals(testUrl);
		delete process.env['TRUSTIFY_DA_BACKEND_URL'];
	});

	test('When TRUSTIFY_DA_BACKEND_URL is set in opts (but not in env), should return that value', () => {
		delete process.env['TRUSTIFY_DA_BACKEND_URL'];
		let testOpts = {
			'TRUSTIFY_DA_BACKEND_URL': testUrl
		};
		let selectedUrl = selectTrustifyDABackend(testOpts);
		expect(selectedUrl).to.be.equals(testUrl);
	});

	test('When TRUSTIFY_DA_BACKEND_URL is set in both environment and opts, opts should take precedence', () => {
		process.env['TRUSTIFY_DA_BACKEND_URL'] = testUrl;
		let testOpts = {
			'TRUSTIFY_DA_BACKEND_URL': testUrl2
		};
		let selectedUrl = selectTrustifyDABackend(testOpts);
		expect(selectedUrl).to.be.equals(testUrl2);
		delete process.env['TRUSTIFY_DA_BACKEND_URL'];
	});

	test('When TRUSTIFY_DA_BACKEND_URL is not set, should throw error', () => {
		delete process.env['TRUSTIFY_DA_BACKEND_URL'];
		expect(() => selectTrustifyDABackend({})).to.throw('TRUSTIFY_DA_BACKEND_URL is unset');
	});

	test('When TRUSTIFY_DA_BACKEND_URL is empty string in environment, should throw error', () => {
		process.env['TRUSTIFY_DA_BACKEND_URL'] = '';
		expect(() => selectTrustifyDABackend({})).to.throw('TRUSTIFY_DA_BACKEND_URL is unset');
		delete process.env['TRUSTIFY_DA_BACKEND_URL'];
	});

	test('When TRUSTIFY_DA_BACKEND_URL is empty string in opts, should throw error', () => {
		delete process.env['TRUSTIFY_DA_BACKEND_URL'];
		let testOpts = {
			'TRUSTIFY_DA_BACKEND_URL': ''
		};
		expect(() => selectTrustifyDABackend(testOpts)).to.throw('TRUSTIFY_DA_BACKEND_URL is unset');
	});

	test('When TRUSTIFY_DA_BACKEND_URL is null in opts, should throw error', () => {
		delete process.env['TRUSTIFY_DA_BACKEND_URL'];
		let testOpts = {
			'TRUSTIFY_DA_BACKEND_URL': null
		};
		expect(() => selectTrustifyDABackend(testOpts)).to.throw('TRUSTIFY_DA_BACKEND_URL is unset');
	});
});

suite('verify token header logging', () => {
	suiteSetup(() => sinon.spy(console, 'log'));
	suiteTeardown(() => console.log.restore());

	test('don\'t log the token header', () => {
		getTokenHeaders({
			'TRUSTIFY_DA_TOKEN': 'banana',
			'TRUSTIFY_DA_DEBUG': 'true'
		})
		expect(console.log).to.be.calledOnce
	})
});
