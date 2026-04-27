import fs from 'node:fs'
import path from 'node:path'

import { parse as parseToml } from 'smol-toml'

import { environmentVariableIsPopulated, getCustom, getCustomPath, invokeCommand } from '../tools.js'

import Base_pyproject from './base_pyproject.js'
import { evaluateMarker } from './marker_evaluator.js'

export default class Python_poetry extends Base_pyproject {

	/**
	 * Poetry has no native workspace/monorepo support (python-poetry/poetry#2270).
	 * Each poetry project is treated independently — no lock file walk-up.
	 * Running `poetry show` from a parent directory returns the parent's deps, not
	 * the sub-package's, so walk-up would produce incorrect SBOMs.
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
		const dir = path.resolve(manifestDir)
		return fs.existsSync(path.join(dir, this._lockFileName())) ? dir : null
	}

	/** @returns {string} */
	_lockFileName() {
		return 'poetry.lock'
	}

	/** @returns {string} */
	_cmdName() {
		return 'poetry'
	}

	/**
	 * @param {string} manifestDir
	 * @param {string} _workspaceDir - unused (poetry has no workspace support)
	 * @param {object} parsed - parsed pyproject.toml
	 * @param {Object} opts
	 * @returns {Promise<{directDeps: string[], graph: Map<string, {name: string, version: string, children: string[]}>}>}
	 */
	// eslint-disable-next-line no-unused-vars
	async _getDependencyData(manifestDir, _workspaceDir, parsed, opts) {
		let hasDevGroup = !!(parsed.tool?.poetry?.group?.dev || parsed.tool?.poetry?.['dev-dependencies'])
		let treeOutput = this._getPoetryShowTreeOutput(manifestDir, hasDevGroup, opts)
		let showAllOutput = this._getPoetryShowAllOutput(manifestDir, opts)
		let versionMap = this._parsePoetryShowAll(showAllOutput)
		let lockDir = this._findLockFileDir(manifestDir, opts)
		let markerData = this._extractMarkerData(lockDir, parsed)
		return this._parsePoetryTree(treeOutput, versionMap, markerData)
	}

	/**
	 * Get poetry show --tree output.
	 * @param {string} manifestDir
	 * @param {boolean} hasDevGroup
	 * @param {Object} opts
	 * @returns {string}
	 */
	_getPoetryShowTreeOutput(manifestDir, hasDevGroup, opts) {
		if (environmentVariableIsPopulated('TRUSTIFY_DA_POETRY_SHOW_TREE')) {
			return Buffer.from(process.env['TRUSTIFY_DA_POETRY_SHOW_TREE'], 'base64').toString('utf-8')
		}
		let poetryBin = getCustomPath('poetry', opts)
		let args = ['show', '--tree', '--no-ansi']
		if (hasDevGroup) {
			args.push('--without', 'dev')
		}
		return invokeCommand(poetryBin, args, { cwd: manifestDir }).toString()
	}

	/**
	 * Get poetry show --all output (flat list with resolved versions).
	 * @param {string} manifestDir
	 * @param {Object} opts
	 * @returns {string}
	 */
	_getPoetryShowAllOutput(manifestDir, opts) {
		if (environmentVariableIsPopulated('TRUSTIFY_DA_POETRY_SHOW_ALL')) {
			return Buffer.from(process.env['TRUSTIFY_DA_POETRY_SHOW_ALL'], 'base64').toString('utf-8')
		}
		let poetryBin = getCustomPath('poetry', opts)
		return invokeCommand(poetryBin, ['show', '--no-ansi', '--all'], { cwd: manifestDir }).toString()
	}

	/**
	 * Parse poetry show --all output into a version map.
	 * Lines look like: "name         (!) 1.2.3  Description text..."
	 * or:              "name             1.2.3  Description text..."
	 * @param {string} output
	 * @returns {Map<string, string>} canonical name -> version
	 */
	_parsePoetryShowAll(output) {
		let versions = new Map()
		let lines = output.split(/\r?\n/)
		for (let line of lines) {
			let trimmed = line.trim()
			if (!trimmed) { continue }
			let match = trimmed.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)\s+(?:\(!\)\s+)?(\S+)/)
			if (match) {
				versions.set(this._canonicalize(match[1]), match[2])
			}
		}
		return versions
	}

	/**
	 * Collects PEP 508 marker expressions for direct and transitive deps.
	 * Direct markers come from pyproject.toml dependency strings, e.g.:
	 *   "pywin32>=311 ; sys_platform == 'win32'"  → directMarkers['pywin32'] = "sys_platform == 'win32'"
	 * Transitive markers come from poetry.lock [package.dependencies] entries, e.g.:
	 *   colorama = {version = "*", markers = "sys_platform == 'win32'"}
	 *   → transitiveMarkers['click']['colorama'] = "sys_platform == 'win32'"
	 * @param {string|null} lockDir
	 * @param {object} parsed - parsed pyproject.toml
	 * @returns {{directMarkers: Map<string, string>, transitiveMarkers: Map<string, Map<string, string>>}}
	 */
	_extractMarkerData(lockDir, parsed) {
		let directMarkers = new Map()
		let transitiveMarkers = new Map()

		// Extract markers from PEP 621 dependency strings: "name[extras]>=ver ; marker"
		let deps = parsed.project?.dependencies || []
		for (let dep of deps) {
			let m = dep.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)\s*[^;]*;\s*(.+)$/)
			if (m) {
				directMarkers.set(this._canonicalize(m[1]), m[2].trim())
			}
		}

		if (lockDir) {
			let lockPath = path.join(lockDir, this._lockFileName())
			if (fs.existsSync(lockPath)) {
				let lockContent = fs.readFileSync(lockPath, 'utf-8')
				let lock = parseToml(lockContent)
				let packages = lock.package || []
				for (let pkg of packages) {
					let pkgKey = this._canonicalize(pkg.name)
					let pkgDeps = pkg.dependencies || {}
					for (let [depName, depSpec] of Object.entries(pkgDeps)) {
						let markers = typeof depSpec === 'object' && depSpec != null ? depSpec.markers : null
						if (markers) {
							if (!transitiveMarkers.has(pkgKey)) {
								transitiveMarkers.set(pkgKey, new Map())
							}
							transitiveMarkers.get(pkgKey).set(this._canonicalize(depName), markers)
						}
					}
				}
			}
		}

		return { directMarkers, transitiveMarkers }
	}

	/**
	 * Parse poetry show --tree output into a dependency graph structure.
	 *
	 * @param {string} treeOutput
	 * @param {Map<string, string>} versionMap - canonical name -> resolved version
	 * @param {{directMarkers: Map<string, string>, transitiveMarkers: Map<string, Map<string, string>>}} markerData
	 * @returns {{directDeps: string[], graph: Map<string, {name: string, version: string, children: string[]}>}}
	 */
	_parsePoetryTree(treeOutput, versionMap, markerData) {
		let lines = treeOutput.split(/\r?\n/)
		let graph = new Map()
		let directDeps = []

		let stack = [] // [{key, depth}]
		let currentDirectDep = null

		for (let line of lines) {
			if (!line.trim()) { continue }

			// top-level line: "name version description..."
			let topMatch = line.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)\s+(\S+)(?:\s|$)/)
			if (topMatch) {
				let name = topMatch[1]
				let version = topMatch[2]
				let key = this._canonicalize(name)

				let marker = markerData.directMarkers.get(key)
				if (marker && !evaluateMarker(marker)) {
					currentDirectDep = null
					stack = []
					continue
				}

				directDeps.push(key)
				if (!graph.has(key)) {
					graph.set(key, { name, version, children: [] })
				}
				currentDirectDep = key
				stack = [{ key, depth: -1 }]
				continue
			}

			if (!currentDirectDep) { continue }

			// indented line with tree chars (UTF-8 box-drawing: ├── └── │)
			let nameStart = line.search(/[A-Za-z0-9]/)
			if (nameStart < 0) { continue }

			let rest = line.substring(nameStart)
			let depMatch = rest.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)/)
			if (!depMatch) { continue }

			let depName = depMatch[1]
			let depKey = this._canonicalize(depName)

			// determine depth by counting tree-drawing groups in the prefix
			let prefix = line.substring(0, nameStart)
			let depth = (prefix.match(/(?:[├└│ ][\s─]{2} ?)/g) || []).length

			// pop stack back to find the parent at depth-1
			while (stack.length > 0 && stack[stack.length - 1].depth >= depth) {
				stack.pop()
			}

			let parentKey = stack.length > 0 ? stack[stack.length - 1].key : null
			if (parentKey) {
				let parentMarkers = markerData.transitiveMarkers.get(parentKey)
				if (parentMarkers) {
					let marker = parentMarkers.get(depKey)
					if (marker && !evaluateMarker(marker)) {
						continue
					}
				}
			}

			// resolve version from the version map
			let version = versionMap.get(depKey) || null
			if (!version) {
				throw new Error(`poetry: package '${depName}' has no resolved version`)
			}

			if (!graph.has(depKey)) {
				graph.set(depKey, { name: depName, version, children: [] })
			}

			if (parentKey) {
				let parentEntry = graph.get(parentKey)
				if (parentEntry && !parentEntry.children.includes(depKey)) {
					parentEntry.children.push(depKey)
				}
			}

			stack.push({ key: depKey, depth })
		}

		return { directDeps, graph }
	}
}
