import fs from 'node:fs'
import path from 'node:path'

import { PackageURL } from 'packageurl-js'
import { parse as parseToml } from 'smol-toml'

import { getLicense } from '../license/license_utils.js'
import Sbom from '../sbom.js'
import { getCustomPath, invokeCommand } from '../tools.js'

export default { isSupported, validateLockFile, provideComponent, provideStack, readLicenseFromManifest }

/** @typedef {import('../provider').Provider} */

/** @typedef {import('../provider').Provided} Provided */

/**
 * @type {string} ecosystem identifier for cargo/crates packages
 * @private
 */
const ecosystem = 'cargo'

/**
 * Ignore markers recognised in Cargo.toml comments.
 * Supports both the legacy `exhortignore` marker and the new `trustify-da-ignore` marker.
 * @type {string[]}
 * @private
 */
const IGNORE_MARKERS = ['exhortignore', 'trustify-da-ignore']

/**
 * Checks whether a line contains any of the recognised ignore markers.
 * @param {string} line - the line to check
 * @returns {boolean} true if the line contains at least one ignore marker
 * @private
 */
function hasIgnoreMarker(line) {
	return IGNORE_MARKERS.some(marker => line.includes(marker))
}

/**
 * Checks whether a dependency name is in the ignored set, accounting for
 * Cargo's underscore/hyphen equivalence
 * @param {string} name - the dependency name to check
 * @param {Set<string>} ignoredDeps - set of ignored dependency names
 * @returns {boolean} true if the dependency should be ignored
 * @private
 */
function isDepIgnored(name, ignoredDeps) {
	if (ignoredDeps.has(name)) {return true}
	let normalized = name.replace(/_/g, '-')
	if (normalized !== name && ignoredDeps.has(normalized)) {return true}
	normalized = name.replace(/-/g, '_')
	if (normalized !== name && ignoredDeps.has(normalized)) {return true}
	return false
}

/**
 * Enum-like constants for Cargo project types.
 * @private
 */
const CrateType = {
	SINGLE_CRATE: 'SINGLE_CRATE',
	WORKSPACE_VIRTUAL: 'WORKSPACE_VIRTUAL',
	WORKSPACE_WITH_ROOT_CRATE: 'WORKSPACE_WITH_ROOT_CRATE'
}

/**
 * @param {string} manifestName - the subject manifest name-type
 * @returns {boolean} - return true if `Cargo.toml` is the manifest name-type
 */
function isSupported(manifestName) {
	return 'Cargo.toml' === manifestName
}

/**
 * Read project license from Cargo.toml, with fallback to LICENSE file.
 * Supports the `license` field under `[package]` (single crate / workspace
 * with root) and under `[workspace.package]` (virtual workspaces).
 * @param {string} manifestPath - path to Cargo.toml
 * @returns {string|null} SPDX identifier or null
 */
function readLicenseFromManifest(manifestPath) {
	let fromManifest = null
	try {
		let content = fs.readFileSync(manifestPath, 'utf-8')
		let parsed = parseToml(content)

		fromManifest = parsed.package?.license
			|| parsed.workspace?.package?.license
			|| null
	} catch (_) {
		// leave fromManifest as null
	}
	return getLicense(fromManifest, manifestPath)
}

/**
 * Validates that Cargo.lock exists in the manifest directory or in a parent
 * workspace root directory.  In Cargo workspaces the lock file always lives at
 * the workspace root, so when a member crate's Cargo.toml is provided we walk
 * up the directory tree looking for Cargo.lock (stopping when we find a
 * Cargo.toml that contains a [workspace] section, or when we reach the
 * filesystem root).
 * @param {string} manifestDir - the directory where the manifest lies
 * @returns {boolean} true if Cargo.lock is found
 */
function validateLockFile(manifestDir) {
	let dir = path.resolve(manifestDir)
	let parent = dir

	do {
		dir = parent

		if (fs.existsSync(path.join(dir, 'Cargo.lock'))) {
			return true
		}

		// If this directory has a Cargo.toml with [workspace], the lock file
		// should have been here — stop searching.
		let cargoToml = path.join(dir, 'Cargo.toml')
		if (fs.existsSync(cargoToml)) {
			try {
				let content = fs.readFileSync(cargoToml, 'utf-8')
				if (/\[workspace\]/.test(content)) {
					return false
				}
			} catch (_) {
				// ignore read errors, keep searching
			}
		}

		parent = path.dirname(dir)
	} while (parent !== dir)

	return false
}

/**
 * Provide content and content type for Cargo stack analysis.
 * @param {string} manifest - the manifest path
 * @param {{}} [opts={}] - optional various options to pass along the application
 * @returns {Provided}
 */
function provideStack(manifest, opts = {}) {
	return {
		ecosystem,
		content: getSBOM(manifest, opts, true),
		contentType: 'application/vnd.cyclonedx+json'
	}
}

/**
 * Provide content and content type for Cargo component analysis.
 * @param {string} manifest - path to Cargo.toml for component report
 * @param {{}} [opts={}] - optional various options to pass along the application
 * @returns {Provided}
 */
function provideComponent(manifest, opts = {}) {
	return {
		ecosystem,
		content: getSBOM(manifest, opts, false),
		contentType: 'application/vnd.cyclonedx+json'
	}
}

/**
 * Create SBOM json string for a Cargo project.
 * @param {string} manifest - path to Cargo.toml
 * @param {{}} [opts={}] - optional various options to pass along the application
 * @param {boolean} includeTransitive - whether the sbom should contain transitive dependencies
 * @returns {string} the SBOM json content
 * @private
 */
function getSBOM(manifest, opts = {}, includeTransitive) {
	let cargoBin = getCustomPath('cargo', opts)
	verifyCargoAccessible(cargoBin)

	let manifestDir = path.dirname(manifest)
	let metadata = executeCargoMetadata(cargoBin, manifestDir)
	let ignoredDeps = getIgnoredDeps(manifest, metadata)
	let crateType = detectCrateType(metadata)
	let license = readLicenseFromManifest(manifest)

	let sbom
	if (crateType === CrateType.WORKSPACE_VIRTUAL) {
		sbom = handleVirtualWorkspace(manifest, metadata, ignoredDeps, includeTransitive, opts, license)
	} else {
		sbom = handleSingleCrate(metadata, ignoredDeps, includeTransitive, opts, license)
	}

	return sbom
}

/**
 * Verifies that the cargo binary is accessible.
 * @param {string} cargoBin - path to cargo binary
 * @throws {Error} if cargo is not accessible
 * @private
 */
function verifyCargoAccessible(cargoBin) {
	try {
		invokeCommand(cargoBin, ['--version'])
	} catch (error) {
		if (error.code === 'ENOENT') {
			throw new Error(`cargo binary is not accessible at "${cargoBin}"`)
		}
		throw new Error('failed to check for cargo binary', { cause: error })
	}
}

/**
 * Executes `cargo metadata` and returns the parsed JSON.
 * @param {string} cargoBin - path to cargo binary
 * @param {string} manifestDir - directory containing Cargo.toml
 * @returns {object} parsed cargo metadata JSON
 * @throws {Error} if cargo metadata fails
 * @private
 */
function executeCargoMetadata(cargoBin, manifestDir) {
	try {
		let output = invokeCommand(cargoBin, ['metadata', '--format-version', '1'], { cwd: manifestDir })
		return JSON.parse(output.toString().trim())
	} catch (error) {
		throw new Error('failed to execute cargo metadata', { cause: error })
	}
}

/**
 * Detects the type of Cargo project from metadata.
 * @param {object} metadata - parsed cargo metadata
 * @returns {string} one of CrateType values
 * @private
 */
function detectCrateType(metadata) {
	let rootPackageId = metadata.resolve?.root
	let workspaceMembers = metadata.workspace_members || []

	if (!rootPackageId && workspaceMembers.length > 0) {
		return CrateType.WORKSPACE_VIRTUAL
	}

	if (rootPackageId && workspaceMembers.length > 1) {
		return CrateType.WORKSPACE_WITH_ROOT_CRATE
	}

	return CrateType.SINGLE_CRATE
}

/**
 * Handles SBOM generation for single crate and workspace-with-root-crate projects.
 * For workspace-with-root-crate, workspace members are only included if they
 * appear in the root crate's dependency graph from cargo metadata.  We don't
 * automatically add all members as dependencies since most workspace members
 * (examples, tools, benchmarks) depend ON the root crate, not the other way around.
 * @param {object} metadata - parsed cargo metadata
 * @param {Set<string>} ignoredDeps - set of ignored dependency names
 * @param {boolean} includeTransitive - whether to include transitive dependencies
 * @param {{}} opts - options
 * @param {string|null} license - SPDX license identifier for the root component
 * @returns {string} SBOM json string
 * @private
 */
function handleSingleCrate(metadata, ignoredDeps, includeTransitive, opts, license) {
	let rootPackageId = metadata.resolve.root
	let rootPackage = findPackageById(metadata, rootPackageId)
	let rootPurl = toPurl(rootPackage.name, rootPackage.version)

	let sbom = new Sbom()
	sbom.addRoot(rootPurl, license)

	let resolveNode = findResolveNode(metadata, rootPackageId)
	if (!resolveNode) {
		return sbom.getAsJsonString(opts)
	}

	if (includeTransitive) {
		addTransitiveDeps(sbom, metadata, rootPackageId, ignoredDeps, new Set(), rootPurl)
	} else {
		addDirectDeps(sbom, metadata, rootPackageId, rootPurl, ignoredDeps)
	}

	return sbom.getAsJsonString(opts)
}

/**
 * Handles SBOM generation for virtual workspace projects.
 *
 * For stack analysis (includeTransitive=true):
 *   Iterates all workspace members and walks their full dependency trees.
 *
 * For component analysis (includeTransitive=false):
 *   Only includes dependencies explicitly listed in [workspace.dependencies]
 *   of the root Cargo.toml.  If that section is absent the SBOM contains only
 *   the synthetic workspace root with no dependencies — this matches the Java
 *   client behaviour where CA "just analyzes direct dependencies defined in
 *   Cargo.toml".
 *
 * @param {string} manifest - path to the root Cargo.toml
 * @param {object} metadata - parsed cargo metadata
 * @param {Set<string>} ignoredDeps - set of ignored dependency names
 * @param {boolean} includeTransitive - whether to include transitive dependencies
 * @param {{}} opts - options
 * @param {string|null} license - SPDX license identifier for the root component
 * @returns {string} SBOM json string
 * @private
 */
function handleVirtualWorkspace(manifest, metadata, ignoredDeps, includeTransitive, opts, license) {
	let workspaceRoot = metadata.workspace_root
	let rootName = path.basename(workspaceRoot)
	let workspaceVersion = getWorkspaceVersion(metadata)
	let rootPurl = toPurl(rootName, workspaceVersion)

	let sbom = new Sbom()
	sbom.addRoot(rootPurl, license)

	if (includeTransitive) {
		// Stack analysis: walk all members and their full dependency trees
		let workspaceMembers = metadata.workspace_members || []

		for (let memberId of workspaceMembers) {
			let memberPackage = findPackageById(metadata, memberId)
			if (!memberPackage) {continue}

			let memberPurl = memberPackage.source == null
				? toPathDepPurl(memberPackage.name, memberPackage.version)
				: toPurl(memberPackage.name, memberPackage.version)

			sbom.addDependency(rootPurl, memberPurl)
			addTransitiveDeps(sbom, metadata, memberId, ignoredDeps, new Set(), memberPurl)
		}
	} else {
		// Component analysis: only [workspace.dependencies] from root Cargo.toml
		let workspaceDeps = getWorkspaceDepsFromManifest(manifest)

		for (let depName of workspaceDeps) {
			if (isDepIgnored(depName, ignoredDeps)) {continue}

			let pkg = metadata.packages.find(p => p.name === depName)
			if (!pkg) {
				let altName = depName.replace(/-/g, '_')
				pkg = metadata.packages.find(p => p.name === altName)
			}
			if (!pkg) {continue}

			let depPurl = pkg.source == null
				? toPathDepPurl(pkg.name, pkg.version)
				: toPurl(pkg.name, pkg.version)

			sbom.addDependency(rootPurl, depPurl)
		}
	}

	return sbom.getAsJsonString(opts)
}

/**
 * Recursively adds transitive dependencies to the SBOM.
 * Path dependencies (source == null) are included with a
 * {@code repository_url=local} qualifier so the backend can skip
 * vulnerability checks while still showing them in the dependency tree.
 * @param {Sbom} sbom - the SBOM to add dependencies to
 * @param {object} metadata - parsed cargo metadata
 * @param {string} packageId - the package ID to resolve dependencies for
 * @param {Set<string>} ignoredDeps - set of ignored dependency names
 * @param {Set<string>} visited - set of already-visited package IDs to prevent cycles
 * @param {PackageURL} [startingPurl] - purl to use for the starting package,
 *   so callers can ensure it matches the purl already added to the SBOM
 * @private
 */
function addTransitiveDeps(sbom, metadata, packageId, ignoredDeps, visited, startingPurl) {
	if (visited.has(packageId)) {return}
	visited.add(packageId)

	let resolveNode = findResolveNode(metadata, packageId)
	if (!resolveNode) {return}

	let sourcePackage = findPackageById(metadata, packageId)
	if (!sourcePackage) {return}

	let sourcePurl = startingPurl || (sourcePackage.source == null
		? toPathDepPurl(sourcePackage.name, sourcePackage.version)
		: toPurl(sourcePackage.name, sourcePackage.version))

	let runtimeDeps = filterRuntimeDeps(resolveNode)

	for (let depId of runtimeDeps) {
		let depPackage = findPackageById(metadata, depId)
		if (!depPackage) {continue}
		if (isDepIgnored(depPackage.name, ignoredDeps)) {continue}

		let depPurl = depPackage.source == null
			? toPathDepPurl(depPackage.name, depPackage.version)
			: toPurl(depPackage.name, depPackage.version)

		sbom.addDependency(sourcePurl, depPurl)
		addTransitiveDeps(sbom, metadata, depId, ignoredDeps, visited)
	}
}

/**
 * Adds only direct (non-transitive) dependencies to the SBOM.
 * Path dependencies are included with a {@code repository_url=local} qualifier.
 * @param {Sbom} sbom - the SBOM to add dependencies to
 * @param {object} metadata - parsed cargo metadata
 * @param {string} packageId - the package ID to resolve dependencies for
 * @param {PackageURL} parentPurl - the parent purl to attach dependencies to
 * @param {Set<string>} ignoredDeps - set of ignored dependency names
 * @private
 */
function addDirectDeps(sbom, metadata, packageId, parentPurl, ignoredDeps) {
	let resolveNode = findResolveNode(metadata, packageId)
	if (!resolveNode) {return}

	let runtimeDeps = filterRuntimeDeps(resolveNode)

	for (let depId of runtimeDeps) {
		let depPackage = findPackageById(metadata, depId)
		if (!depPackage) {continue}
		if (isDepIgnored(depPackage.name, ignoredDeps)) {continue}

		let depPurl = depPackage.source == null
			? toPathDepPurl(depPackage.name, depPackage.version)
			: toPurl(depPackage.name, depPackage.version)

		sbom.addDependency(parentPurl, depPurl)
	}
}

/**
 * Filters the deps of a resolve node to only include runtime (normal) dependencies.
 * @param {object} resolveNode - a node from metadata.resolve.nodes
 * @returns {string[]} array of package IDs for runtime dependencies
 * @private
 */
function filterRuntimeDeps(resolveNode) {
	if (!resolveNode.deps) {return []}

	return resolveNode.deps
		.filter(dep => {
			if (!dep.dep_kinds || dep.dep_kinds.length === 0) {return true}
			return dep.dep_kinds.some(dk => dk.kind == null || dk.kind === 'normal')
		})
		.map(dep => dep.pkg)
}

/**
 * Finds a package in the metadata by its ID.
 * @param {object} metadata - parsed cargo metadata
 * @param {string} packageId - the package ID to find
 * @returns {object|undefined} the found package or undefined
 * @private
 */
function findPackageById(metadata, packageId) {
	return metadata.packages.find(pkg => pkg.id === packageId)
}

/**
 * Finds a resolve node by package ID.
 * @param {object} metadata - parsed cargo metadata
 * @param {string} packageId - the package ID to find
 * @returns {object|undefined} the found resolve node or undefined
 * @private
 */
function findResolveNode(metadata, packageId) {
	return metadata.resolve.nodes.find(node => node.id === packageId)
}

/**
 * Parses the root Cargo.toml and returns the dependency names listed in the
 * [workspace.dependencies] section.  Returns an empty array when the section
 * does not exist.
 * @param {string} manifest - path to the root Cargo.toml
 * @returns {string[]} list of dependency names
 * @private
 */
function getWorkspaceDepsFromManifest(manifest) {
	let content = fs.readFileSync(manifest, 'utf-8')
	let parsed = parseToml(content)
	return Object.keys(parsed.workspace?.dependencies || {})
}

/**
 * Extracts the workspace version from metadata if defined.
 * @param {object} metadata - parsed cargo metadata
 * @returns {string} the workspace version or a placeholder
 * @private
 */
function getWorkspaceVersion(metadata) {
	let workspaceRoot = metadata.workspace_root
	let cargoTomlPath = path.join(workspaceRoot, 'Cargo.toml')
	try {
		let content = fs.readFileSync(cargoTomlPath, 'utf-8')
		let parsed = parseToml(content)
		return parsed.workspace?.package?.version || '0.0.0'
	} catch (_) {
		return '0.0.0'
	}
}

/**
 * Parses Cargo.toml for dependencies annotated with an ignore marker.
 * Supports both `exhortignore` and `trustify-da-ignore` markers.
 * Supports inline deps, table-based deps, and workspace-level dependency sections.
 * Uses cargo metadata to discover workspace members (which already handles glob
 * expansion and exclude filtering) instead of parsing workspace member paths ourselves.
 * @param {string} manifest - path to Cargo.toml
 * @param {object} metadata - parsed cargo metadata
 * @returns {Set<string>} set of dependency names to ignore
 * @private
 */
function getIgnoredDeps(manifest, metadata) {
	let ignored = new Set()

	scanManifestForIgnored(manifest, ignored)

	// Scan workspace member manifests using metadata
	let manifestDir = path.dirname(manifest)
	let workspaceRoot = metadata.workspace_root
	let workspaceMembers = metadata.workspace_members || []

	for (let memberId of workspaceMembers) {
		let memberRelDir = getMemberRelativeDir(memberId, workspaceRoot)
		if (memberRelDir == null) {continue}

		let memberManifest = path.join(manifestDir, memberRelDir, 'Cargo.toml')
		if (path.resolve(memberManifest) === path.resolve(manifest)) {continue}

		if (fs.existsSync(memberManifest)) {
			scanManifestForIgnored(memberManifest, ignored)
		}
	}

	return ignored
}

/**
 * Extracts a workspace member's directory path relative to the workspace root
 * from its cargo package ID.  Workspace member IDs use the `path+file://` scheme,
 * e.g. `path+file:///workspace/root/crates/member#0.1.0`.
 * @param {string} packageId - the cargo package ID
 * @param {string} workspaceRoot - the workspace root path from cargo metadata
 * @returns {string|null} relative directory path, or null if it cannot be determined
 * @private
 */
function getMemberRelativeDir(packageId, workspaceRoot) {
	let pathMatch = packageId.match(/path\+file:\/\/(.+?)#/)
	if (!pathMatch) {return null}

	let pkgPath = pathMatch[1]
	if (!pkgPath.startsWith(workspaceRoot)) {return null}

	let relPath = pkgPath.substring(workspaceRoot.length)
	if (relPath.startsWith('/')) {relPath = relPath.substring(1)}

	return relPath || null
}

/**
 * Scans a single Cargo.toml for ignored dependencies and adds them to the set.
 * @param {string} manifest - path to Cargo.toml
 * @param {Set<string>} ignored - the set to add ignored dependency names to
 * @private
 */
function scanManifestForIgnored(manifest, ignored) {
	let content = fs.readFileSync(manifest, 'utf-8')
	let lines = content.split(/\r?\n/)

	let currentSection = ''
	let currentDepName = null

	for (let line of lines) {
		let trimmed = line.trim()

		let sectionMatch = trimmed.match(/^\[([^\]]+)\]\s*(?:#.*)?$/)
		if (sectionMatch) {
			currentSection = sectionMatch[1]
			currentDepName = null

			let tableDep = currentSection.match(/^(?:dependencies|dev-dependencies|build-dependencies|workspace\.dependencies)\.(.+)$/)
			if (tableDep) {
				currentDepName = tableDep[1]
				// If the section header line itself carries an ignore marker,
				// immediately add the dep
				if (hasIgnoreMarker(line)) {
					ignored.add(currentDepName)
				}
			}
			continue
		}

		let isIgnored = hasIgnoreMarker(line)

		if (isIgnored && isInDependencySection(currentSection)) {
			let inlineMatch = trimmed.match(/^([a-zA-Z0-9_-]+)\s*=/)
			if (inlineMatch) {
				ignored.add(inlineMatch[1])
				continue
			}
		}

		if (isIgnored && currentDepName) {
			ignored.add(currentDepName)
			continue
		}
	}
}

/**
 * Checks if a section name is a dependency section.
 * @param {string} section - the TOML section name
 * @returns {boolean}
 * @private
 */
function isInDependencySection(section) {
	return section === 'dependencies' ||
		section === 'dev-dependencies' ||
		section === 'build-dependencies' ||
		section === 'workspace.dependencies'
}

/**
 * Creates a PackageURL for a Cargo/crates.io package.
 * @param {string} name - the crate name
 * @param {string} version - the crate version
 * @returns {PackageURL} the package URL
 * @private
 */
function toPurl(name, version) {
	return new PackageURL(ecosystem, undefined, name, version, undefined, undefined)
}

/**
 * Creates a PackageURL for a local path dependency, marked with a
 * {@code repository_url=local} qualifier so the backend can distinguish
 * it from registry packages and skip vulnerability checks.
 * @param {string} name - the crate name
 * @param {string} version - the crate version
 * @returns {PackageURL} the package URL with local qualifier
 * @private
 */
function toPathDepPurl(name, version) {
	return new PackageURL(ecosystem, undefined, name, version, { repository_url: 'local' }, undefined)
}
