import { expect } from 'chai'

import { selectExhortBackend } from '../src/index.js'

const testProdUrl = 'https://exhort.example.com';
const testDevUrl = 'https://dev.exhort.example.com';

suite('testing Select Exhort Backend function when TRUSTIFY_DA_DEV_MODE environment variable is True', () => {

	test('When Dev Mode environment Variable= true, default DEV Exhort Backend Selected', () => {
		let testOpts = {
			'TRUSTIFY_DA_DEV_MODE': 'true'
		}
		let selectedUrl = selectExhortBackend(testOpts);
		expect(selectedUrl).not.to.be.equals(testProdUrl)
		expect(selectedUrl).to.be.equals(testDevUrl)
	});

	test('When Dev Mode environment Variable= true, and despite option Dev Mode = false, default DEV Exhort Backend Selected', () => {
		let testOpts = {
			'TRUSTIFY_DA_DEV_MODE': 'false'
		}
		let selectedUrl = selectExhortBackend(testOpts);
		expect(selectedUrl).not.to.be.equals(testProdUrl)
		expect(selectedUrl).to.be.equals(testDevUrl)
	});

	test('When Dev Mode environment Variable= true, And option DEV_TRUSTIFY_DA_BACKEND_URL contains some url route that client set, default DEV Exhort Backend Not Selected', () => {
		const dummyRoute = 'http://dummy-exhort-route';
		delete process.env['DEV_TRUSTIFY_DA_BACKEND_URL']
		let testOpts = {
			'DEV_TRUSTIFY_DA_BACKEND_URL': dummyRoute
		}
		let selectedUrl = selectExhortBackend(testOpts);
		expect(selectedUrl).to.be.equals(dummyRoute)
	});

}).beforeAll(() => {
	process.env['TRUSTIFY_DA_DEV_MODE'] = 'true'
	process.env['TRUSTIFY_DA_BACKEND_URL'] = testProdUrl
	process.env['DEV_TRUSTIFY_DA_BACKEND_URL'] = testDevUrl
}).afterAll(() => delete process.env['TRUSTIFY_DA_DEV_MODE']);

suite('testing Select Exhort Backend function when TRUSTIFY_DA_DEV_MODE environment variable is false', () => {

	test('When Dev Mode environment Variable= true, default DEV Exhort Backend Selected', () => {

		let testOpts = {
			'TRUSTIFY_DA_DEV_MODE': 'false'
		}
		let selectedUrl = selectExhortBackend(testOpts);
		expect(selectedUrl).not.to.be.equals(testDevUrl)
		expect(selectedUrl).to.be.equals(testProdUrl)
	});

	test('When Dev Mode environment Variable= false, and despite option Dev Mode = true, default Exhort Backend Selected (production)', () => {
		let dummyRoute = 'http://dummy-dev-route-exhort'
		let testOpts = {
			'TRUSTIFY_DA_DEV_MODE': 'true',
			'DEV_TRUSTIFY_DA_BACKEND_URL': dummyRoute
		}
		let selectedUrl = selectExhortBackend(testOpts);
		expect(selectedUrl).not.to.be.equals(dummyRoute)
		expect(selectedUrl).to.be.equals(testProdUrl)
	});

	test('When Dev Mode environment Variable= false, environment variable DEV_TRUSTIFY_DA_BACKEND_URL=dummy-url, option TRUSTIFY_DA_DEV_MODE=true, default Exhort Backend Selected anyway', () => {
		const dummyRoute = 'http://dummy-url'
		process.env['DEV_TRUSTIFY_DA_BACKEND_URL'] = dummyRoute
		let testOpts = {
			'TRUSTIFY_DA_DEV_MODE': 'true',
			'DEV_TRUSTIFY_DA_BACKEND_URL': dummyRoute
		}
		let selectedUrl = selectExhortBackend(testOpts);
		delete process.env['DEV_TRUSTIFY_DA_BACKEND_URL']
		expect(selectedUrl).not.to.be.equals(dummyRoute)
		expect(selectedUrl).to.be.equals(testProdUrl)
	});

}).beforeAll(() => {
	process.env['TRUSTIFY_DA_DEV_MODE'] = 'false'
	process.env['TRUSTIFY_DA_BACKEND_URL'] = testProdUrl
	process.env['DEV_TRUSTIFY_DA_BACKEND_URL'] = testDevUrl
}).afterAll(() => delete process.env['TRUSTIFY_DA_DEV_MODE']);

suite('testing Select Exhort Backend function when TRUSTIFY_DA_DEV_MODE environment variable is not set', () => {

	test('When Dev Mode Option = false, default Exhort Backend Selected (production)', () => {

		let testOpts = {
			'TRUSTIFY_DA_DEV_MODE': 'false'
		}
		let selectedUrl = selectExhortBackend(testOpts);
		expect(selectedUrl).not.to.be.equals(testDevUrl)
		expect(selectedUrl).to.be.equals(testProdUrl)
	});

	test('When Dev Mode Option Variable= true, default dev Exhort Backend Selected', () => {
		let testOpts = {
			'TRUSTIFY_DA_DEV_MODE': 'true'
		}
		let selectedUrl = selectExhortBackend(testOpts);
		expect(selectedUrl).not.to.be.equals(testProdUrl)
		expect(selectedUrl).to.be.equals(testDevUrl)
	});

	test('When Dev Mode option = true, option DEV_TRUSTIFY_DA_BACKEND_URL=some dummy-url, then some dummy-url Selected', () => {
		let dummyRoute = 'http://dummy-dev-route-exhort'
		process.env['DEV_TRUSTIFY_DA_BACKEND_URL'] = dummyRoute
		let testOpts = {
			'TRUSTIFY_DA_DEV_MODE': 'true',
			'DEV_TRUSTIFY_DA_BACKEND_URL': dummyRoute
		}
		let selectedUrl = selectExhortBackend(testOpts);
		expect(selectedUrl).not.to.be.equals(testProdUrl)
		expect(selectedUrl).to.be.equals(dummyRoute)
		delete process.env['DEV_TRUSTIFY_DA_BACKEND_URL']
	});

	test('When Nothing set, throw error', () => {
		let selectedUrl = selectExhortBackend({});
		expect(selectedUrl).to.be.equals(testProdUrl)
	})
}).beforeAll(() => {
	process.env['TRUSTIFY_DA_BACKEND_URL'] = testProdUrl;
	process.env['DEV_TRUSTIFY_DA_BACKEND_URL'] = testDevUrl
});
