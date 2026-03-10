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

	test('When TRUSTIFY_DA_BACKEND_URL is set in both environment and opts, environment variable should take precedence', () => {
		process.env['TRUSTIFY_DA_BACKEND_URL'] = testUrl;
		let testOpts = {
			'TRUSTIFY_DA_BACKEND_URL': testUrl2
		};
		let selectedUrl = selectTrustifyDABackend(testOpts);
		expect(selectedUrl).to.be.equals(testUrl);
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

}).afterAll(() => {
	delete process.env['TRUSTIFY_DA_BACKEND_URL'];
});

suite('verify token header logging', () => {
	test('don\'t log the token header', () => {
		getTokenHeaders({
			'TRUSTIFY_DA_TOKEN': 'banana',
			'TRUSTIFY_DA_DEBUG': 'true'
		})
		// Should only be called once with "Headers Values to be sent to Trustify DA backend:"
		expect(console.log).to.be.calledOnce
	})
}).beforeAll(() => sinon.spy(console, 'log')).afterAll(() => console.log.restore())
