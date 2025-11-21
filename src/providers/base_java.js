import fs from 'node:fs'
import path from 'node:path'

import { PackageURL } from 'packageurl-js'

import { getCustomPath, getGitRootDir, getWrapperPreference, invokeCommand } from "../tools.js"


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
		let targetDepth = this.#getDepth(target);
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
				this.parseDependencyTree(lines[index - 1], this.#getDepth(lines[index - 1]), lines.slice(index), sbom)
			}
			target = lines[++index];
			targetDepth = this.#getDepth(target);
		}
	}

	/**
	 * Calculates how deep in the graph is the given line
	 * @param {string} line - line to calculate the depth from
	 * @returns {number} The calculated depth
	 * @private
	 */
	#getDepth(line) {
		if (line === undefined) {
			return -1;
		}
		return ((line.indexOf('-') - 1) / 3) + 1;
	}

	/**
	 * Create a PackageURL from any line in a Text Graph dependency tree for a manifest path.
	 * @param {string} line - line to parse from a dependencies.txt file
	 * @returns {PackageURL} The parsed packageURL
	 */
	parseDep(line) {
		let match = line.split(':').map(part => part ? part.match(this.DEP_REGEX)[0] : '');
		if (!match) {
			throw new Error(`Unable generate SBOM from dependency tree. Line: ${line} cannot be parsed into a PackageURL`);
		}
		let version
		if (match.length >= 5 && ['compile', 'provided', 'runtime'].includes(match[5])) {
			version = `${match[4]}-${match[3]}`
		} else {
			version = match[3]
		}
		let override = line.match(this.CONFLICT_REGEX);
		if (override) {
			version = override[1];
		}
		if (match[0].trim() === '') {
			throw new Error(`Artifact coordinates should have a non-empty group ID: ${line}`);
		}
		return this.toPurl(match[0], match[1], version);
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
			const wrapper = this.traverseForWrapper(manifestPath)
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

	/**
	 *
	 * @param {string} startingManifest - the path of the manifest from which to start searching for the wrapper
	 * @param {string} repoRoot - the root of the repository at which point to stop searching for mvnw, derived via git if unset and then fallsback
	 * to the root of the drive the manifest is on (assumes absolute path is given)
	 * @returns {string|undefined}
	 */
	traverseForWrapper(startingManifest, repoRoot = undefined) {
		const normalizedManifest = this.normalizePath(startingManifest);
		const currentDir = this.normalizePath(path.dirname(normalizedManifest));
		repoRoot = repoRoot || getGitRootDir(currentDir) || path.parse(normalizedManifest).root;
		const wrapperPath = path.join(currentDir, this.localWrapper);

		try {
			fs.accessSync(wrapperPath, fs.constants.X_OK);
			return wrapperPath;
		}
		catch (error) {
			if (error.code === 'ENOENT') {
				const rootDir = path.parse(currentDir).root;
				if (currentDir === repoRoot || currentDir === rootDir) {
					return undefined;
				}
				const parentDir = path.dirname(currentDir);
				if (parentDir === currentDir || parentDir === rootDir) {
					return undefined;
				}
				return this.traverseForWrapper(path.join(parentDir, path.basename(normalizedManifest)), repoRoot);
			}
			throw new Error(`failure searching for ${this.localWrapper}`, { cause: error });
		}
	}

	normalizePath(thePath) {
		const normalized = path.resolve(thePath).normalize();
		return process.platform === 'win32' ? normalized.toLowerCase() : normalized;
	}
}
