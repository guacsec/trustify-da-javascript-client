import { environmentVariableIsPopulated, getCustomPath, invokeCommand } from '../tools.js'

import Base_pyproject from './base_pyproject.js'

/**
 * Python provider for pyproject.toml files using PEP 621 format without a lock file.
 * Uses `pip install --dry-run --ignore-installed --report` to resolve the full dependency tree.
 * Acts as the fallback provider when no lock file (uv.lock/poetry.lock) is found.
 */
export default class Python_pip_pyproject extends Base_pyproject {

	/** @returns {string} */
	_lockFileName() {
		return '.pip-lock-nonexistent'
	}

	/** @returns {string} */
	_cmdName() {
		return 'pip'
	}

	/**
	 * Always returns true — pip provider is the fallback when no lock file is found.
	 * @param {string} manifestDir
	 * @param {{}} [opts={}]
	 * @returns {boolean}
	 */
	// eslint-disable-next-line no-unused-vars
	validateLockFile(manifestDir, opts = {}) {
		return true
	}

	/**
	 * Get pip report output from env var override or by running pip.
	 * @param {string} manifestDir - directory containing pyproject.toml
	 * @param {{}} [opts={}]
	 * @returns {string} pip report JSON string
	 */
	_getPipReportOutput(manifestDir, opts) {
		if (environmentVariableIsPopulated('TRUSTIFY_DA_PIP_REPORT')) {
			return Buffer.from(process.env['TRUSTIFY_DA_PIP_REPORT'], 'base64').toString('ascii')
		}
		let pipBin = getCustomPath('pip3', opts)
		try {
			invokeCommand(pipBin, ['--version'])
		} catch {
			pipBin = getCustomPath('pip', opts)
		}
		return invokeCommand(pipBin, [
			'install', '--dry-run', '--ignore-installed', '--report', '-', '.'
		], { cwd: manifestDir }).toString()
	}

	/**
	 * Parse pip report JSON and build dependency graph.
	 * @param {string} reportJson - pip report JSON string
	 * @returns {{directDeps: string[], graph: Map<string, {name: string, version: string, children: string[]}>}}
	 */
	_parsePipReport(reportJson) {
		let report = JSON.parse(reportJson)
		let packages = report.install || []

		let rootEntry = packages.find(p => p.download_info?.dir_info !== undefined)
		let rootRequires = rootEntry?.metadata?.requires_dist || []

		let directDepNames = new Set()
		for (let req of rootRequires) {
			if (this._hasExtraMarker(req)) { continue }
			let name = this._extractDepName(req)
			if (name) { directDepNames.add(this._canonicalize(name)) }
		}

		let graph = new Map()
		let nonRootPackages = packages.filter(p => p.download_info?.dir_info === undefined)

		for (let pkg of nonRootPackages) {
			let name = pkg.metadata.name
			let version = pkg.metadata.version
			let key = this._canonicalize(name)
			graph.set(key, { name, version, children: [] })
		}

		for (let pkg of nonRootPackages) {
			let key = this._canonicalize(pkg.metadata.name)
			let entry = graph.get(key)
			let requires = pkg.metadata.requires_dist || []
			for (let req of requires) {
				if (this._hasExtraMarker(req)) { continue }
				let depName = this._extractDepName(req)
				if (!depName) { continue }
				let depKey = this._canonicalize(depName)
				if (graph.has(depKey)) {
					entry.children.push(depKey)
				}
			}
		}

		let directDeps = [...directDepNames].filter(key => graph.has(key))
		return { directDeps, graph }
	}

	/**
	 * Check if a requires_dist entry is an extras-only dependency.
	 * @param {string} req - e.g. "PySocks!=1.5.7,>=1.5.6; extra == \"socks\""
	 * @returns {boolean}
	 */
	_hasExtraMarker(req) {
		return /;\s*.*extra\s*==/.test(req)
	}

	/**
	 * Extract package name from a requires_dist entry.
	 * @param {string} req - e.g. "charset_normalizer<4,>=2"
	 * @returns {string|null}
	 */
	_extractDepName(req) {
		let match = req.match(/^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)/)
		return match ? match[1] : null
	}

	/**
	 * Resolve dependencies using pip install --dry-run --report.
	 * @param {string} manifestDir
	 * @param {object} parsed - parsed pyproject.toml
	 * @param {{}} [opts={}]
	 * @returns {Promise<{directDeps: string[], graph: Map}>}
	 */
	async _getDependencyData(manifestDir, parsed, opts) {
		let reportOutput = this._getPipReportOutput(manifestDir, opts)
		return this._parsePipReport(reportOutput)
	}
}
