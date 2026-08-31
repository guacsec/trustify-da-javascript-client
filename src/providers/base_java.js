import path from 'node:path'

import { PackageURL } from 'packageurl-js'

import { getCustomPath, getWrapperPreference, invokeCommand, traverseForWrapper } from "../tools.js"

/** @typedef {import('../provider').Provider} */

/** @typedef {import('../provider').Provided} Provided */

/** @typedef {{name: string, version: string}} Package */

/** @typedef {{groupId: string, artifactId: string, version: string, scope: string, ignore: boolean}} Dependency */

/**
 * @type {string} ecosystem for java maven packages.
 * @private
 */
export const ecosystem_maven = 'maven'
export const ecosystem_gradle = 'gradle'
export default class Base_Java {
	DEP_REGEX = /(([-a-zA-Z0-9._]{2,})|[0-9])/g
	CONFLICT_REGEX = /.*omitted for conflict with (\S+)\)/

	/**
	 * Maven dependency scopes. Used to detect whether the trailing column of a
	 * dependency-tree line is a scope keyword — which in turn signals that an
	 * optional classifier column is present between the packaging and version.
	 * @type {string[]}
	 */
	static MAVEN_SCOPES = ['compile', 'provided', 'runtime', 'test', 'system', 'import']

	globalBinary
	localWrapper

	/**
	 *
	 * @param {string} globalBinary name of the global binary
	 * @param {string} localWrapper name of the local wrapper filename
	 */
	constructor(globalBinary, localWrapper) {
		this.globalBinary = globalBinary
		this.localWrapper = localWrapper
	}

	/**
	 * Returns the package manager name (e.g. mvn, gradle)
	 * @returns {string}
	 */
	packageManagerName() {
		return this.globalBinary
	}

	/**
	 * Recursively populates the SBOM instance with the parsed graph
	 * @param {string} src - Source dependency to start the calculations from
	 * @param {number} srcDepth - Current depth in the graph for the given source
	 * @param {Array} lines - Array containing the text files being parsed
	 * @param {Sbom} sbom - The SBOM where the dependencies are being added
	 */
	parseDependencyTree(src, srcDepth, lines, sbom) {
		if (lines.length === 0) {
			return;
		}
		if ((lines.length === 1 && lines[0].trim() === "")) {
			return;
		}
		let index = 0;
		let target = lines[index];
		let targetDepth = this._getDepth(target);
		while (targetDepth > srcDepth && index < lines.length) {
			if (targetDepth === srcDepth + 1) {
				let from = this.parseDep(src);
				let to = this.parseDep(target);
				let matchedScope = target.match(/:compile|:provided|:runtime|:test|:system|:import/g)
				let matchedScopeSrc = src.match(/:compile|:provided|:runtime|:test|:system|:import/g)
				// only add dependency to sbom if it's not with test scope or if it's root
				if ((matchedScope && matchedScope[0] !== ":test" && (matchedScopeSrc && matchedScopeSrc[0] !== ":test")) || (srcDepth === 0 && matchedScope && matchedScope[0] !== ":test")) {
					sbom.addDependency(from, to)
				}
			} else {
				this.parseDependencyTree(lines[index - 1], this._getDepth(lines[index - 1]), lines.slice(index), sbom)
			}
			target = lines[++index];
			targetDepth = this._getDepth(target);
		}
	}

	/**
	 * Calculates how deep in the graph is the given line
	 * @param {string} line - line to calculate the depth from
	 * @returns {number} The calculated depth
	 * @protected
	 */
	_getDepth(line) {
		if (!line || line.trim() === '') { return -1; }
		if (line.match(/^\w/)) { return 0; }
		return ((line.indexOf('-') - 1) / 3) + 1;
	}

	/**
	 * Parse a single dependency-tree line into its Maven coordinate parts.
	 *
	 * This is the single source of truth for interpreting a dependency-tree
	 * line. Both {@link parseDep} (used to build SBOM component PURLs) and the
	 * Maven hash-map builder rely on it, so the PURL key and the artifact file
	 * path can never drift from one another.
	 *
	 * A line has the shape `groupId:artifactId:packaging[:classifier]:version[:scope]`.
	 * The classifier column is only present when a sixth column holds a known
	 * Maven scope keyword; otherwise the fourth column is the version.
	 *
	 * @param {string} line - line to parse from a dependency tree
	 * @returns {{groupId: string, artifactId: string, packaging: string, classifier: (string|null), version: string, scope: (string|null), overridden: boolean}}
	 *   Parsed coordinate. `version` is the resolved concrete version — when the
	 *   line carries a conflict override the override version replaces it and
	 *   `overridden` is set, mirroring how Maven records the winning version.
	 */
	parseCoordinate(line) {
		const parts = line.split(':').map(part => part ? part.match(this.DEP_REGEX)?.[0] ?? '' : '')
		const groupId = parts[0] ?? ''
		const artifactId = parts[1] ?? ''
		const packaging = parts[2] ?? ''
		// A classifier column exists only when a sixth column holds a scope keyword.
		const hasClassifier = parts.length >= 6 && Base_Java.MAVEN_SCOPES.includes(parts[5])
		const classifier = hasClassifier ? parts[3] : null
		let version = (hasClassifier ? parts[4] : parts[3]) ?? ''
		const scope = hasClassifier ? parts[5] : (parts.length >= 5 ? parts[4] : null)
		// A conflict override replaces the resolved version entirely.
		const override = line.match(this.CONFLICT_REGEX)
		const overridden = Boolean(override)
		if (overridden) {
			version = override[1]
		}
		return { groupId, artifactId, packaging, classifier, version, scope, overridden }
	}

	/**
	 * Build the canonical PackageURL for a parsed coordinate.
	 *
	 * The classifier is folded into the version component (e.g.
	 * `4.1.0-linux-x86_64`) except when the version came from a conflict
	 * override, in which case the override version stands alone — matching the
	 * historical behavior of {@link parseDep}.
	 *
	 * @param {{groupId: string, artifactId: string, classifier: (string|null), version: string, overridden: boolean}} coord
	 * @returns {PackageURL} The canonical packageURL for the coordinate
	 * @protected
	 */
	_coordinateToPurl(coord) {
		const purlVersion = (coord.classifier && !coord.overridden)
			? `${coord.version}-${coord.classifier}`
			: coord.version
		return this.toPurl(coord.groupId, coord.artifactId, purlVersion)
	}

	/**
	 * Create a PackageURL from any line in a Text Graph dependency tree for a manifest path.
	 * @param {string} line - line to parse from a dependencies.txt file
	 * @returns {PackageURL} The parsed packageURL
	 */
	parseDep(line) {
		const coord = this.parseCoordinate(line)
		if (coord.groupId.trim() === '') {
			throw new Error(`Artifact coordinates should have a non-empty group ID: ${line}`);
		}
		return this._coordinateToPurl(coord);
	}

	/**
	 * Returns a PackageUrl For Java maven dependencies
	 * @param group
	 * @param artifact
	 * @param version
	 * @return {PackageURL}
	 */
	toPurl(group, artifact, version) {
		if (typeof version === "number") {
			version = version.toString()
		}
		return new PackageURL('maven', group, artifact, version, undefined, undefined);
	}

	/** This method invokes command string in a process in a synchronous way.
	 * Exists for stubbing in tests.
	 * @param bin - the command to be invoked
	 * @param args - the args to pass to the binary
	 * @param {import('child_process').ExecFileOptionsWithStringEncoding} [opts={}]
	 * @protected
	 */
	_invokeCommand(bin, args, opts={}) { return invokeCommand(bin, args, opts) }

	/**
	 *
	 * @param {string} manifestPath
	 * @param {{}} opts
	 * @returns string
	 */
	selectToolBinary(manifestPath, opts) {
		const manifestDir = path.dirname(manifestPath)
		const toolPath = getCustomPath(this.globalBinary, opts)

		const useWrapper = getWrapperPreference(this.globalBinary, opts)
		if (useWrapper) {
			const wrapper = traverseForWrapper(manifestDir, this.localWrapper)
			if (wrapper !== undefined) {
				try {
					this._invokeCommand(wrapper, ['--version'], {cwd: manifestDir})
				} catch (error) {
					throw new Error(`failed to check for ${this.localWrapper}`, {cause: error})
				}
				return wrapper
			}
		}
		// verify tool is accessible, if wrapper was not requested or not found
		try {
			this._invokeCommand(toolPath, ['--version'], {cwd: manifestDir})
		} catch (error) {
			if (error.code === 'ENOENT') {
				throw new Error((useWrapper ? `${this.localWrapper} not found and ` : '') + `${this.globalBinary === 'mvn' ? 'maven' : 'gradle'} not found at ${toolPath}`)
			} else {
				throw new Error(`failed to check for ${this.globalBinary === 'mvn' ? 'maven' : 'gradle'}`, {cause: error})
			}
		}
		return toolPath
	}

}
