import fs from 'node:fs'
import path from 'node:path'

import fg from 'fast-glob'
import { parse as parseToml } from 'smol-toml'

import { environmentVariableIsPopulated, getCustomPath, invokeCommand } from '../tools.js'
import { filterManifestPathsByDiscoveryIgnore, resolveWorkspaceDiscoveryIgnore, toManifestGlobPatterns } from '../workspace.js'

import Base_pyproject from './base_pyproject.js'
import { evaluateMarker } from './marker_evaluator.js'
import { getParser, getPinnedVersionQuery } from './requirements_parser.js'

export default class Python_uv extends Base_pyproject {

	/** @returns {string} */
	_lockFileName() {
		return 'uv.lock'
	}

	/** @returns {string} */
	_cmdName() {
		return 'uv'
	}

	/**
	 * @param {string} manifestDir - directory containing the target pyproject.toml
	 * @param {string} workspaceDir - workspace root (for resolving editable install paths)
	 * @param {object} parsed - parsed pyproject.toml
	 * @param {Object} opts
	 * @returns {Promise<{directDeps: string[], graph: Map<string, import('./base_pyproject.js').GraphEntry>}>}
	 */
	async _getDependencyData(manifestDir, workspaceDir, parsed, opts) {
		let projectName = this._getProjectName(parsed)
		let uvOutput = this._getUvExportOutput(manifestDir, opts)
		let { directDeps, graph } = await this._parseUvExport(uvOutput, projectName, workspaceDir)
		await this._attachHashesFromLockFile(path.join(workspaceDir, 'uv.lock'), graph)
		return { directDeps, graph }
	}

	/**
	 * Parse uv.lock and attach SHA-256 hashes to graph entries.
	 * @param {string} lockFilePath - path to uv.lock
	 * @param {Map<string, import('./base_pyproject.js').GraphEntry>} graph
	 */
	async _attachHashesFromLockFile(lockFilePath, graph) {
		let lockContent
		try {
			lockContent = await fs.promises.readFile(lockFilePath, 'utf-8')
		} catch {
			return
		}

		let parsed
		try {
			parsed = parseToml(lockContent)
		} catch {
			return
		}

		let packages = parsed.package
		if (!Array.isArray(packages)) { return }

		for (let pkg of packages) {
			if (!pkg.name) { continue }
			let hashStr = pkg.sdist?.hash || pkg.wheels?.[0]?.hash
			if (!hashStr || !hashStr.startsWith('sha256:')) { continue }

			let key = this._canonicalize(pkg.name)
			let entry = graph.get(key)
			if (!entry || entry.hashes) { continue }

			entry.hashes = [{alg: "SHA-256", content: hashStr.slice(7)}]
		}
	}

	/**
	 * Get the uv export output, either from env var or by running the command.
	 * @param {string} manifestDir
	 * @param {Object} opts
	 * @returns {string}
	 */
	_getUvExportOutput(manifestDir, opts) {
		if (environmentVariableIsPopulated('TRUSTIFY_DA_UV_EXPORT')) {
			return Buffer.from(process.env['TRUSTIFY_DA_UV_EXPORT'], 'base64').toString('ascii')
		}
		let uvBin = getCustomPath('uv', opts)
		return invokeCommand(uvBin, ['export', '--format', 'requirements.txt', '--frozen', '--no-hashes', '--no-dev', '--no-emit-project'], { cwd: manifestDir }).toString()
	}

	/**
	 * Parse uv export output into a dependency graph using tree-sitter-requirements
	 * for package/version extraction and string parsing for "# via" comments.
	 *
	 * @param {string} output
	 * @param {string} projectName - canonical project name to identify direct deps
	 * @param {string} workspaceDir - workspace root (for resolving editable install paths)
	 * @returns {Promise<{directDeps: string[], graph: Map<string, {name: string, version: string, children: string[]}>}>}
	 */
	async _parseUvExport(output, projectName, workspaceDir) {
		let [parser, pinnedVersionQuery] = await Promise.all([
			getParser(), getPinnedVersionQuery()
		])
		let tree = parser.parse(output)
		let root = tree.rootNode
		let canonProjectName = this._canonicalize(projectName)

		let packages = new Map() // canonical name -> {name, version, parents: Set}
		let currentPkg = null
		let collectingVia = false

		for (let child of root.children) {
			if (child.type === 'global_opt') {
				let optNode = child.children.find(c => c.type === 'option')
				let pathNode = child.children.find(c => c.type === 'path')
				if (optNode?.text === '-e' && pathNode && workspaceDir) {
					let memberDir = path.resolve(workspaceDir, pathNode.text)
					let memberManifest = path.join(memberDir, 'pyproject.toml')
					if (fs.existsSync(memberManifest)) {
						let memberParsed = parseToml(fs.readFileSync(memberManifest, 'utf-8'))
						let name = memberParsed.project?.name || memberParsed.tool?.poetry?.name
						let version = memberParsed.project?.version || memberParsed.tool?.poetry?.version
						if (name && version) {
							let key = this._canonicalize(name)
							if (key === canonProjectName) { continue }
							currentPkg = { name, version, parents: new Set() }
							packages.set(key, currentPkg)
							collectingVia = false
							continue
						}
					}
				}
				currentPkg = null
				collectingVia = false
				continue
			}

			if (child.type === 'requirement') {
				let nameNode = child.children.find(c => c.type === 'package')
				if (!nameNode) { continue }

				// Skip packages with non-matching PEP 508 markers, e.g. "pywin32==311 ; sys_platform == 'win32'"
				let markerNode = child.children.find(c => c.type === 'marker_spec')
				if (markerNode) {
					let markerText = markerNode.text.replace(/^\s*;\s*/, '')
					if (!evaluateMarker(markerText)) {
						currentPkg = null
						collectingVia = false
						continue
					}
				}

				let name = nameNode.text
				let version = null
				let versionMatches = pinnedVersionQuery.matches(child)
				if (versionMatches.length > 0) {
					version = versionMatches[0].captures.find(c => c.name === 'version').node.text
				}

				if (!version) {
					throw new Error(`uv export: package '${name}' has no pinned version`)
				}

				let key = this._canonicalize(name)
				currentPkg = { name, version, parents: new Set() }
				packages.set(key, currentPkg)
				collectingVia = false
				continue
			}

			if (child.type === 'comment' && currentPkg) {
				let text = child.text.trim()

				let viaSingle = text.match(/^# via ([A-Za-z0-9][A-Za-z0-9._-]*)$/)
				if (viaSingle) {
					currentPkg.parents.add(this._canonicalize(viaSingle[1]))
					collectingVia = false
					continue
				}

				if (text === '# via') {
					collectingVia = true
					continue
				}

				if (collectingVia) {
					let parentMatch = text.match(/^#\s+([A-Za-z0-9][A-Za-z0-9._-]*)$/)
					if (parentMatch) {
						currentPkg.parents.add(this._canonicalize(parentMatch[1]))
						continue
					}
					collectingVia = false
				}
			}
		}

		// Build forward dependency map and extract direct deps in one pass
		let graph = new Map()
		let directDeps = []

		for (let [key, pkg] of packages) {
			graph.set(key, { name: pkg.name, version: pkg.version, children: [] })
		}
		for (let [childKey, pkg] of packages) {
			for (let parentKey of pkg.parents) {
				if (parentKey === canonProjectName) {
					directDeps.push(childKey)
					continue
				}
				let parentEntry = graph.get(parentKey)
				if (parentEntry) {
					parentEntry.children.push(childKey)
				}
			}
		}

		return { directDeps, graph }
	}
}

const DEFAULT_UV_DISCOVERY_IGNORE = [
	'**/__pycache__/**',
	'**/.venv/**',
]

/**
 * Discover all pyproject.toml manifest paths in a uv workspace.
 * Parses `[tool.uv.workspace]` from root pyproject.toml and glob-expands member patterns.
 *
 * @param {string} workspaceRoot - Absolute or relative path to workspace root (must contain pyproject.toml and uv.lock)
 * @param {{ workspaceDiscoveryIgnore?: string[], TRUSTIFY_DA_WORKSPACE_DISCOVERY_IGNORE?: string, [key: string]: unknown }} [opts={}]
 * @returns {Promise<string[]>} Paths to pyproject.toml files (absolute)
 */
export async function discoverUvWorkspaceMembers(workspaceRoot, opts = {}) {
	const root = path.resolve(workspaceRoot)
	const rootPyproject = path.join(root, 'pyproject.toml')
	const uvLock = path.join(root, 'uv.lock')

	if (!fs.existsSync(rootPyproject) || !fs.existsSync(uvLock)) {
		return []
	}

	let parsed
	try {
		parsed = parseToml(fs.readFileSync(rootPyproject, 'utf-8'))
	} catch {
		return []
	}

	const workspaceConfig = parsed?.tool?.uv?.workspace
	if (!workspaceConfig) {
		return []
	}

	const memberPatterns = workspaceConfig.members
	if (!Array.isArray(memberPatterns) || memberPatterns.length === 0) {
		return []
	}

	const excludePatterns = Array.isArray(workspaceConfig.exclude) ? workspaceConfig.exclude : []
	const excludeGlobs = excludePatterns
		.filter(p => typeof p === 'string' && p.trim())
		.map(p => `${p.trim()}/pyproject.toml`)

	const ignorePatterns = [...resolveWorkspaceDiscoveryIgnore(opts), ...DEFAULT_UV_DISCOVERY_IGNORE]
	const globOpts = {
		cwd: root,
		absolute: true,
		onlyFiles: true,
		ignore: [...ignorePatterns, ...excludeGlobs],
		followSymbolicLinks: false,
	}

	const patterns = toManifestGlobPatterns(
		memberPatterns.filter(p => typeof p === 'string'),
		'pyproject.toml',
	)
	const manifestPaths = await fg(patterns, globOpts)

	if (!manifestPaths.includes(rootPyproject) && hasProjectMetadata(parsed)) {
		manifestPaths.unshift(rootPyproject)
	}

	return filterManifestPathsByDiscoveryIgnore(manifestPaths, root, ignorePatterns)
}

/**
 * @param {import('smol-toml').TomlTable} parsedPyProject
 * @returns {boolean}
 */
function hasProjectMetadata(parsedPyProject) {
	try {
		return typeof parsedPyProject?.project?.name === 'string' && parsedPyProject.project.name.trim() !== ''
	} catch {
		return false
	}
}
