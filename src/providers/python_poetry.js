import { environmentVariableIsPopulated, getCustomPath, invokeCommand } from '../tools.js'

import Base_pyproject from './base_pyproject.js'

export default class Python_poetry extends Base_pyproject {

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
	 * @param {object} parsed - parsed pyproject.toml
	 * @param {Object} opts
	 * @returns {Promise<{directDeps: string[], graph: Map<string, {name: string, version: string, children: string[]}>}>}
	 */
	async _getDependencyData(manifestDir, parsed, opts) {
		let treeOutput = this._getPoetryShowTreeOutput(manifestDir, opts)
		let showAllOutput = this._getPoetryShowAllOutput(manifestDir, opts)
		let versionMap = this._parsePoetryShowAll(showAllOutput)
		return this._parsePoetryTree(treeOutput, versionMap)
	}

	/**
	 * Get poetry show --tree output.
	 * @param {string} manifestDir
	 * @param {Object} opts
	 * @returns {string}
	 */
	_getPoetryShowTreeOutput(manifestDir, opts) {
		if (environmentVariableIsPopulated('TRUSTIFY_DA_POETRY_SHOW_TREE')) {
			return Buffer.from(process.env['TRUSTIFY_DA_POETRY_SHOW_TREE'], 'base64').toString('utf-8')
		}
		let poetryBin = getCustomPath('poetry', opts)
		return invokeCommand(poetryBin, ['show', '--tree', '--no-ansi'], { cwd: manifestDir }).toString()
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
	 * Parse poetry show --tree output into a dependency graph structure.
	 * Top-level lines (no indentation/tree chars) are direct deps: "name version description"
	 * Indented lines are transitive deps with tree chars: "├── name >=constraint"
	 *
	 * @param {string} treeOutput
	 * @param {Map<string, string>} versionMap - canonical name -> resolved version
	 * @returns {{directDeps: string[], graph: Map<string, {name: string, version: string, children: string[]}>}}
	 */
	_parsePoetryTree(treeOutput, versionMap) {
		let lines = treeOutput.split(/\r?\n/)
		let graph = new Map()
		let directDeps = []

		let stack = [] // [{key, depth}]
		let currentDirectDep = null

		for (let line of lines) {
			if (!line.trim()) { continue }

			// top-level line: "name version description..."
			let topMatch = line.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)\s+(\S+)\s/)
			if (topMatch) {
				let name = topMatch[1]
				let version = topMatch[2]
				let key = this._canonicalize(name)
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

			// resolve version from the version map
			let version = versionMap.get(depKey) || null
			if (!version) {
				throw new Error(`poetry: package '${depName}' has no resolved version`)
			}

			if (!graph.has(depKey)) {
				graph.set(depKey, { name: depName, version, children: [] })
			}

			// pop stack back to find the parent at depth-1
			while (stack.length > 0 && stack[stack.length - 1].depth >= depth) {
				stack.pop()
			}

			if (stack.length > 0) {
				let parentKey = stack[stack.length - 1].key
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
