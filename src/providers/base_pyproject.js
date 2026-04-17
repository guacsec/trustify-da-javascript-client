import fs from 'node:fs'
import path from 'node:path'

import { PackageURL } from 'packageurl-js'
import { parse as parseToml } from 'smol-toml'

import { getLicense } from '../license/license_utils.js'
import Sbom from '../sbom.js'
import { getCustom } from '../tools.js'

const ecosystem = 'pip'

const IGNORE_MARKERS = ['exhortignore', 'trustify-da-ignore']

const DEFAULT_ROOT_NAME = 'default-pip-root'
const DEFAULT_ROOT_VERSION = '0.0.0'

/** @typedef {{name: string, version: string, children: string[]}} GraphEntry */
/** @typedef {{name: string, version: string, dependencies: DepTreeEntry[]}} DepTreeEntry */
/** @typedef {{directDeps: string[], graph: Map<string, GraphEntry>}} DependencyData */
/** @typedef {{ecosystem: string, content: string, contentType: string}} Provided */

export default class Base_pyproject {

	/**
	 * @param {string} manifestName
	 * @returns {boolean}
	 */
	isSupported(manifestName) {
		return 'pyproject.toml' === manifestName
	}

	/**
	 * @param {string} manifestDir
	 * @param {Object} [opts={}]
	 * @returns {boolean}
	 */
	validateLockFile(manifestDir, opts = {}) {
		return this._findLockFileDir(manifestDir, opts) != null
	}

	/**
	 * Walk up from manifestDir to find the directory containing the lock file.
	 * Follows the same pattern as Base_javascript._findLockFileDir().
	 * @param {string} manifestDir
	 * @param {Object} [opts={}]
	 * @returns {string|null}
	 * @protected
	 */
	_findLockFileDir(manifestDir, opts = {}) {
		const workspaceDir = getCustom('TRUSTIFY_DA_WORKSPACE_DIR', null, opts)
		if (workspaceDir) {
			const dir = path.resolve(workspaceDir)
			return fs.existsSync(path.join(dir, this._lockFileName())) ? dir : null
		}

		let dir = path.resolve(manifestDir)
		let parent = dir

		do {
			dir = parent

			if (fs.existsSync(path.join(dir, this._lockFileName()))) {
				return dir
			}

			if (this._isWorkspaceRoot(dir)) {
				return null
			}

			parent = path.dirname(dir)
		} while (parent !== dir)

		return null
	}

	/**
	 * Detect workspace root boundaries.
	 * Currently only uv has native workspace support ([tool.uv.workspace] in pyproject.toml).
	 * Poetry has no workspace/monorepo support (python-poetry/poetry#2270), so each
	 * poetry project is treated independently — see Python_poetry._findLockFileDir().
	 * @param {string} dir
	 * @returns {boolean}
	 * @protected
	 */
	_isWorkspaceRoot(dir) {
		const pyprojectPath = path.join(dir, 'pyproject.toml')
		if (!fs.existsSync(pyprojectPath)) {
			return false
		}
		try {
			const content = parseToml(fs.readFileSync(pyprojectPath, 'utf-8'))
			if (content.tool?.uv?.workspace) {
				return true
			}
		} catch (_) {
			// ignore parse errors
		}
		return false
	}

	/**
	 * Read project license from pyproject.toml, with fallback to LICENSE file.
	 * @param {string} manifestPath
	 * @returns {string|null}
	 */
	readLicenseFromManifest(manifestPath) {
		let fromManifest = null
		try {
			let content = fs.readFileSync(manifestPath, 'utf-8')
			let parsed = parseToml(content)
			fromManifest = parsed.project?.license
			if (typeof fromManifest === 'object' && fromManifest != null) {
				fromManifest = fromManifest.text || null
			}
			if (!fromManifest) {
				fromManifest = parsed.tool?.poetry?.license || null
			}
		} catch (_) {
			// leave fromManifest as null
		}
		return getLicense(fromManifest, manifestPath)
	}

	/**
	 * @param {string} manifest - path to pyproject.toml
	 * @param {Object} [opts={}]
	 * @returns {Promise<Provided>}
	 */
	async provideStack(manifest, opts = {}) {
		return {
			ecosystem,
			content: await this._createSbom(manifest, opts, true),
			contentType: 'application/vnd.cyclonedx+json'
		}
	}

	/**
	 * @param {string} manifest - path to pyproject.toml
	 * @param {Object} [opts={}]
	 * @returns {Promise<Provided>}
	 */
	async provideComponent(manifest, opts = {}) {
		return {
			ecosystem,
			content: await this._createSbom(manifest, opts, false),
			contentType: 'application/vnd.cyclonedx+json'
		}
	}

	// --- abstract methods (subclasses must override) ---

	/**
	 * @returns {string}
	 * @protected
	 */
	_lockFileName() {
		throw new TypeError('_lockFileName must be implemented')
	}

	/**
	 * @returns {string}
	 * @protected
	 */
	_cmdName() {
		throw new TypeError('_cmdName must be implemented')
	}

	/**
	 * Resolve dependencies using the tool-specific command and parser.
	 *
	 * @param {string} manifestDir - directory containing the target pyproject.toml
	 * @param {string} workspaceDir - workspace root (where the lock file lives);
	 *   only used by providers that need workspace-level resolution (e.g. uv)
	 * @param {object} parsed - parsed pyproject.toml
	 * @param {Object} opts
	 * @returns {Promise<DependencyData>}
	 * @protected
	 */
	// eslint-disable-next-line no-unused-vars
	async _getDependencyData(manifestDir, workspaceDir, parsed, opts) {
		throw new TypeError('_getDependencyData must be implemented')
	}

	// --- shared helpers ---

	/**
	 * Canonicalize a Python package name per PEP 503.
	 * @param {string} name
	 * @returns {string}
	 * @protected
	 */
	_canonicalize(name) {
		return name.toLowerCase().replace(/[-_.]+/g, '-')
	}

	/**
	 * Get the project name from pyproject.toml.
	 * @param {object} parsed
	 * @returns {string|null}
	 * @protected
	 */
	_getProjectName(parsed) {
		return parsed.project?.name || parsed.tool?.poetry?.name || null
	}

	/**
	 * Get the project version from pyproject.toml.
	 * @param {object} parsed
	 * @returns {string|null}
	 * @protected
	 */
	_getProjectVersion(parsed) {
		return parsed.project?.version || parsed.tool?.poetry?.version || null
	}

	/**
	 * Scan raw pyproject.toml text for dependencies with ignore markers.
	 * @param {string} manifestPath
	 * @returns {Set<string>}
	 * @protected
	 */
	_getIgnoredDeps(manifestPath) {
		let ignored = new Set()
		let content = fs.readFileSync(manifestPath, 'utf-8')
		let lines = content.split(/\r?\n/)

		for (let line of lines) {
			if (!IGNORE_MARKERS.some(m => line.includes(m))) { continue }

			// PEP 621 style: "requests>=2.25" #exhortignore
			let pep621Match = line.match(/^\s*"([^"]+)"/)
			if (pep621Match) {
				let reqStr = pep621Match[1]
				let nameMatch = reqStr.match(/^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)/)
				if (nameMatch) {
					ignored.add(this._canonicalize(nameMatch[1]))
				}
				continue
			}

			// Poetry style: requests = "^2.25" #exhortignore
			let poetryMatch = line.match(/^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*=/)
			if (poetryMatch) {
				ignored.add(this._canonicalize(poetryMatch[1]))
			}
		}

		return ignored
	}

	/**
	 * Compute the set of graph nodes reachable from direct deps, excluding ignored.
	 * @param {Map<string, GraphEntry>} graph
	 * @param {string[]} directDeps
	 * @param {Set<string>} ignoredDeps
	 * @returns {Set<string>}
	 * @protected
	 */
	_reachableNodes(graph, directDeps, ignoredDeps) {
		let reachable = new Set()
		let queue = directDeps.filter(k => !ignoredDeps.has(k) && graph.has(k))
		while (queue.length > 0) {
			let key = queue.shift()
			if (reachable.has(key)) { continue }
			reachable.add(key)
			for (let child of graph.get(key).children) {
				if (!ignoredDeps.has(child) && graph.has(child) && !reachable.has(child)) {
					queue.push(child)
				}
			}
		}
		return reachable
	}

	/**
	 * @param {string} name
	 * @param {string} version
	 * @returns {PackageURL}
	 * @protected
	 */
	_toPurl(name, version) {
		return new PackageURL('pypi', undefined, name, version, undefined, undefined)
	}

	/**
	 * Create SBOM json string for a pyproject.toml project.
	 * @param {string} manifest - path to pyproject.toml
	 * @param {Object} opts
	 * @param {boolean} includeTransitive
	 * @returns {Promise<string>}
	 * @private
	 */
	async _createSbom(manifest, opts, includeTransitive) {
		let manifestDir = path.dirname(manifest)
		let content = fs.readFileSync(manifest, 'utf-8')
		let parsed = parseToml(content)

		let workspaceDir = this._findLockFileDir(manifestDir, opts) || manifestDir
		let { directDeps, graph } = await this._getDependencyData(manifestDir, workspaceDir, parsed, opts)

		let ignoredDeps = this._getIgnoredDeps(manifest)

		let sbom = new Sbom()
		let rootName = this._getProjectName(parsed) || DEFAULT_ROOT_NAME
		let rootVersion = this._getProjectVersion(parsed) || DEFAULT_ROOT_VERSION
		let rootPurl = this._toPurl(rootName, rootVersion)
		let license = this.readLicenseFromManifest(manifest)
		sbom.addRoot(rootPurl, license)

		if (includeTransitive) {
			let reachable = this._reachableNodes(graph, directDeps, ignoredDeps)
			for (let key of directDeps) {
				if (!reachable.has(key)) { continue }
				let entry = graph.get(key)
				sbom.addDependency(rootPurl, this._toPurl(entry.name, entry.version))
			}
			for (let [key, entry] of graph) {
				if (!reachable.has(key)) { continue }
				let parentPurl = this._toPurl(entry.name, entry.version)
				for (let child of entry.children) {
					if (!reachable.has(child)) { continue }
					let childEntry = graph.get(child)
					sbom.addDependency(parentPurl, this._toPurl(childEntry.name, childEntry.version))
				}
			}
		} else {
			for (let key of directDeps) {
				if (ignoredDeps.has(key)) { continue }
				let entry = graph.get(key)
				if (!entry) { continue }
				sbom.addDependency(rootPurl, this._toPurl(entry.name, entry.version))
			}
		}

		return sbom.getAsJsonString(opts)
	}
}
