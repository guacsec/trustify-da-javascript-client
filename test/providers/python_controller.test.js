import { expect } from 'chai'

import Python_controller from '../../src/providers/python_controller.js'

suite('Python_controller BEST_EFFORTS validation', function() {
	let originalBestEfforts

	suiteSetup(function() {
		originalBestEfforts = process.env['TRUSTIFY_DA_PYTHON_INSTALL_BEST_EFFORTS']
	})

	suiteTeardown(function() {
		if (originalBestEfforts === undefined) {
			delete process.env['TRUSTIFY_DA_PYTHON_INSTALL_BEST_EFFORTS']
		} else {
			process.env['TRUSTIFY_DA_PYTHON_INSTALL_BEST_EFFORTS'] = originalBestEfforts
		}
	})

	/** Verifies that BEST_EFFORTS=true without VIRTUAL_ENV=true throws a descriptive error. */
	test('throws when BEST_EFFORTS=true is set without VIRTUAL_ENV=true (realEnvironment=true)', async function() {
		// Given a controller in real environment mode (VIRTUAL_ENV not set)
		process.env['TRUSTIFY_DA_PYTHON_INSTALL_BEST_EFFORTS'] = 'true'
		let controller = new Python_controller(true, 'pip3', 'python3', 'test/providers/tst_manifests/pip/pip_requirements_txt_no_ignore/requirements.txt')

		// When getDependencies is called
		try {
			await controller.getDependencies(false)
			expect.fail('Expected getDependencies to throw')
		} catch (error) {
			// Then the error message names both environment variables
			expect(error.message).to.include('TRUSTIFY_DA_PYTHON_INSTALL_BEST_EFFORTS')
			expect(error.message).to.include('TRUSTIFY_DA_PYTHON_VIRTUAL_ENV')
		}
	})

	/** Verifies that the validation does not trigger when BEST_EFFORTS is false (default). */
	test('does not throw when BEST_EFFORTS is false (default)', async function() {
		// Given a controller in real environment mode with default BEST_EFFORTS
		delete process.env['TRUSTIFY_DA_PYTHON_INSTALL_BEST_EFFORTS']
		let controller = new Python_controller(true, 'pip3', 'python3', 'test/providers/tst_manifests/pip/pip_requirements_txt_no_ignore/requirements.txt')

		// When getDependencies is called, then no BEST_EFFORTS validation error is thrown
		// (it may throw for other reasons like missing pip, which is acceptable)
		try {
			await controller.getDependencies(false)
		} catch (error) {
			expect(error.message).to.not.include('TRUSTIFY_DA_PYTHON_INSTALL_BEST_EFFORTS')
		}
	})

	/** Verifies that BEST_EFFORTS=true with VIRTUAL_ENV=true does not trigger the validation. */
	test('does not throw the validation error when both BEST_EFFORTS=true and VIRTUAL_ENV=true (realEnvironment=false)', async function() {
		this.timeout(120000)
		// Given a controller in virtual environment mode (VIRTUAL_ENV=true)
		process.env['TRUSTIFY_DA_PYTHON_INSTALL_BEST_EFFORTS'] = 'true'
		let controller
		try {
			controller = new Python_controller(false, 'pip3', 'python3', 'test/providers/tst_manifests/pip/pip_requirements_txt_no_ignore/requirements.txt')
		} catch (error) {
			this.skip()
			return
		}

		// When getDependencies is called, then the BEST_EFFORTS+VIRTUAL_ENV validation does not trigger
		// (it may throw for other reasons like venv setup or MATCH_MANIFEST_VERSIONS conflict, which is acceptable)
		try {
			await controller.getDependencies(false)
		} catch (error) {
			expect(error.message).to.not.include('requires TRUSTIFY_DA_PYTHON_VIRTUAL_ENV')
		}
	})
})
