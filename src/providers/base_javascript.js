import fs from 'node:fs'
import os from "node:os";
import path from 'node:path'

import { getLicense } from '../license/license_utils.js'
import Sbom from '../sbom.js'
import { getCustom, getCustomPath, invokeCommand, toPurl, toPurlFromString } from '../tools.js'

import Manifest from './manifest.js';

/** @typedef {import('../provider').Provider} */

/** @typedef {import('../provider').Provided} Provided */

/**
 * The ecosystem identifier for JavaScript/npm packages
 * @type {string}
 */
export const purlType = 'npm';

/**
 * Maps a Subresource Integrity (SRI) algorithm token to its CycloneDX label.
 * @type {Object<string, string>}
 */
const SRI_ALG_LABELS = {
	sha1: 'SHA-1',
	sha256: 'SHA-256',
	sha384: 'SHA-384',
	sha512: 'SHA-512',
};

/**
 * Converts a Subresource Integrity (SRI) string to a CycloneDX hash object.
 * SRI is formatted as `<alg>-<base64>` (e.g. `sha512-Ab3d...`). CycloneDX
 * expects an uppercased algorithm label (e.g. `SHA-512`) and a hex-encoded
 * digest. When the SRI string contains multiple space-separated hashes, only
 * the first is used.
 * @param {string} integrity - SRI string from a lock file
 * @returns {{alg: string, content: string}|null} CycloneDX hash, or null when unparseable
 */
export function sriToHash(integrity) {
	if (typeof integrity !== 'string') {
		return null;
	}
	const first = integrity.trim().split(/\s+/)[0];
	if (!first) {
		return null;
	}
	const dash = first.indexOf('-');
	if (dash < 0) {
		return null;
	}
	const alg = SRI_ALG_LABELS[first.slice(0, dash).toLowerCase()];
	// Strip any SRI options (e.g. "?foo") that may follow the base64 payload
	const base64 = first.slice(dash + 1).split('?')[0];
	if (!alg || !base64) {
		return null;
	}
	const content = Buffer.from(base64, 'base64').toString('hex');
	if (!content) {
		return null;
	}
	return { alg, content };
}

/**
 * Base class for JavaScript package manager providers.
 * This class provides common functionality for different JavaScript package managers
 * (npm, pnpm, yarn) to generate SBOMs and handle package dependencies.
 * @abstract
 */
export default class Base_javascript {
	/** @type {Manifest} */
	#manifest;
	/** @type {string} */
	#cmd;
	/** @type {string} */
	#ecosystem;
	/**
	 * Lock-file hashes keyed by `name@version`.
	 * @type {Map<string, Array<{alg: string, content: string}>>}
	 */
	#hashes = new Map();

	/**
   * Sets up the provider with the manifest path and options
   * @param {string} manifestPath - Path to the package.json manifest file
   * @param {Object} opts - Configuration options for the provider
   * @protected
   */
	_setUp(manifestPath, opts) {
		this.#cmd = getCustomPath(this._cmdName(), opts);
		this.#manifest = new Manifest(manifestPath);
		this.#ecosystem = purlType;
	}

	/**
	 * Gets the current manifest object
	 * @returns {Manifest} The manifest object
	 * @protected
	 */
	_getManifest() {
		return this.#manifest;
	}

	/**
    * Sets the ecosystem value
    * @param {string} ecosystem - The ecosystem identifier
    * @protected
    */
	_setEcosystem(ecosystem) {
		this.#ecosystem = ecosystem;
	}

	/**
   * Returns the name of the lock file for the specific implementation
   * @returns {string} The lock file name
   * @abstract
   * @protected
   */
	_lockFileName() {
		throw new TypeError("_lockFileName must be implemented");
	}

	/**
   * Returns the command name to use for the specific JS package manager
   * @returns {string} The command name
   * @abstract
   * @protected
   */
	_cmdName() {
		throw new TypeError("_cmdName must be implemented");
	}

	/**
   * Returns the package manager name (e.g. npm, yarn, pnpm, bun)
   * @returns {string} The package manager name
   */
	packageManagerName() {
		return this._cmdName();
	}

	/**
   * Returns the command arguments for listing dependencies
   * @returns {Array<string>} The command arguments
   * @abstract
   * @protected
   */
	_listCmdArgs() {
		throw new TypeError("_listCmdArgs must be implemented");
	}

	/**
   * Returns the command arguments for updating the lock file
   * @returns {Array<string>} The command arguments
   * @abstract
   * @protected
   */
	_updateLockFileCmdArgs() {
		throw new TypeError("_updateLockFileCmdArgs must be implemented");
	}

	/**
	 * Parses the provider's lock file into a hash map keyed by `name@version`.
	 * Subclasses override this (accepting the lock directory) to support their
	 * lock file format. The default implementation returns an empty map so
	 * providers without lock parsing (or without a lock file present) gracefully
	 * omit hashes.
	 * @returns {Map<string, Array<{alg: string, content: string}>>} Hash map
	 * @protected
	 */
	_parseLockFileHashes() {
		return new Map();
	}

	/**
	 * Loads lock-file hashes for the given directory into internal state.
	 * Parsing failures degrade gracefully to an empty map (no hashes emitted).
	 * @param {string} lockDir - Directory containing the lock file
	 * @protected
	 */
	_loadHashes(lockDir) {
		try {
			this.#hashes = this._parseLockFileHashes(lockDir) || new Map();
		} catch (_) {
			this.#hashes = new Map();
		}
	}

	/**
	 * Looks up CycloneDX hashes for a package by name and resolved version.
	 * @param {string} name - The package name (including scope, e.g. `@hapi/joi`)
	 * @param {string} version - The resolved package version
	 * @returns {Array<{alg: string, content: string}>|undefined} Hashes, or undefined
	 * @protected
	 */
	_hashesFor(name, version) {
		if (!name || !version) {
			return undefined;
		}
		return this.#hashes.get(`${name}@${version}`);
	}

	/**
	 * Looks up CycloneDX hashes for a package described by a PackageURL.
	 * @param {PackageURL} purl - The package URL
	 * @returns {Array<{alg: string, content: string}>|undefined} Hashes, or undefined
	 * @protected
	 */
	_hashesForPurl(purl) {
		if (!purl) {
			return undefined;
		}
		const name = purl.namespace ? `${purl.namespace}/${purl.name}` : purl.name;
		return this._hashesFor(name, purl.version);
	}

	/**
   * Checks if the provider supports the given manifest name
   * @param {string} manifestName - The manifest name to check
   * @returns {boolean} True if the manifest is supported
   */
	isSupported(manifestName) {
		return 'package.json' === manifestName;
	}

	/**
   * Walks up the directory tree from manifestDir looking for the lock file.
   * Stops when the lock file is found, when a package.json with a "workspaces"
   * field is encountered without a lock file (workspace root boundary), or
   * when the filesystem root is reached.
   *
   * When TRUSTIFY_DA_WORKSPACE_DIR is set, checks only that directory (no walk-up).
   *
   * @param {string} manifestDir - The directory to start searching from
   * @param {Object} [opts={}] - optional; may contain TRUSTIFY_DA_WORKSPACE_DIR
   * @returns {string|null} The directory containing the lock file, or null
   * @protected
   */
	_isWorkspaceRoot(dir) {
		if (fs.existsSync(path.join(dir, 'pnpm-workspace.yaml'))) {
			return true
		}
		const pkgJsonPath = path.join(dir, 'package.json')
		if (fs.existsSync(pkgJsonPath)) {
			try {
				const content = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8'))
				if (content.workspaces) {
					return true
				}
			} catch (_) {
				// ignore parse errors
			}
		}
		return false
	}

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
   * @param {string} manifestDir - The base directory where the manifest is located
   * @param {Object} [opts={}] - optional; may contain TRUSTIFY_DA_WORKSPACE_DIR
   * @returns {boolean} True if the lock file exists
   */
	validateLockFile(manifestDir, opts = {}) {
		return this._findLockFileDir(manifestDir, opts) !== null
	}

	/**
   * Provides content and content type for stack analysis
   * @param {string} manifestPath - The manifest path or name
   * @param {Object} [opts={}] - Optional configuration options
   * @returns {Provided} The provided data for stack analysis
   */
	provideStack(manifestPath, opts = {}) {
		this._setUp(manifestPath, opts);
		return {
			ecosystem: this.#ecosystem,
			content: this.#getSBOM(opts),
			contentType: 'application/vnd.cyclonedx+json'
		}
	}

	/**
   * Provides content and content type for component analysis
   * @param {string} manifestPath - Path to package.json for component report
   * @param {Object} [opts={}] - Optional configuration options
   * @returns {Provided} The provided data for component analysis
   */
	provideComponent(manifestPath, opts = {}) {
		this._setUp(manifestPath, opts);
		return {
			ecosystem: this.#ecosystem,
			content: this.#getDirectDependencySbom(opts),
			contentType: 'application/vnd.cyclonedx+json'
		}
	}

	/**
	 * Read license from manifest (package.json). Reused by npm, pnpm, yarn.
	 * @param {string} manifestPath - path to package.json
	 * @returns {string|null}
	 */
	readLicenseFromManifest(manifestPath) {
		let manifestLicense;
		try {
			const content = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
			if (typeof content.license === 'string') {
				manifestLicense = content.license.trim() || null;
			} else if (Array.isArray(content.licenses) && content.licenses.length > 0) {
				const first = content.licenses[0];
				const name = first.type || first.name;
				manifestLicense = (typeof name === 'string' ? name.trim() : null);
			}
		} catch {
			manifestLicense = null;
		}
		return getLicense(manifestLicense, manifestPath);
	}

	/**
   * Builds the dependency tree for the project
   * @param {boolean} includeTransitive - Whether to include transitive dependencies
   * @param {Object} [opts={}] - Configuration options; when `TRUSTIFY_DA_WORKSPACE_DIR` is set, commands run from workspace root
   * @returns {Object} The dependency tree
   * @protected
   */
	_buildDependencyTree(includeTransitive, opts = {}) {
		this._version();
		const manifestDir = path.dirname(this.#manifest.manifestPath);
		const cmdDir = this._findLockFileDir(manifestDir, opts) || manifestDir;
		this._createLockFile(cmdDir);
		this._loadHashes(cmdDir);

		let output = this.#executeListCmd(includeTransitive, cmdDir);
		output = this._parseDepTreeOutput(output);
		return JSON.parse(output);
	}

	/**
   * Creates SBOM json string for npm Package
   * @param {Object} [opts={}] - Optional configuration options
   * @returns {string} The SBOM json content
   * @private
   */
	#getSBOM(opts = {}) {
		const depsObject = this._buildDependencyTree(true, opts);

		let mainComponent = toPurl(purlType, this.#manifest.name, this.#manifest.version);
		const license = this.readLicenseFromManifest(this.#manifest.manifestPath);

		let sbom = new Sbom();
		sbom.addRoot(mainComponent, license);

		this._addDependenciesToSbom(sbom, depsObject);
		this.#ensurePeerAndOptionalDeps(sbom);
		sbom.filterIgnoredDeps(this.#manifest.ignored);
		return sbom.getAsJsonString(opts);
	}

	/**
	 * Ensures peer and optional dependencies declared in the manifest are
	 * present in the SBOM, even when the package manager does not resolve them
	 * (e.g. yarn does not include peer deps in its dependency listing).
	 * @param {Sbom} sbom - The SBOM to supplement
	 * @private
	 */
	#ensurePeerAndOptionalDeps(sbom) {
		const rootPurl = toPurl(purlType, this.#manifest.name, this.#manifest.version);
		const depSources = [this.#manifest.peerDependencies, this.#manifest.optionalDependencies];
		for (const source of depSources) {
			for (const [name, version] of Object.entries(source)) {
				// Build the purl prefix for exact matching (e.g. "pkg:npm/minimist@"
				// or "pkg:npm/%40hapi/joi@") to avoid substring false positives
				const probe = toPurl(purlType, name, version);
				const purlPrefix = probe.toString().replace(/@[^@]*$/, '@');
				if (!sbom.checkDependsOnByPurlPrefix(rootPurl, purlPrefix)) {
					sbom.addDependency(rootPurl, probe);
				}
			}
		}
	}

	/**
   * Recursively builds the Sbom from the JSON that npm listing returns
   * @param {Sbom} sbom - The SBOM object to add dependencies to
   * @param {Object} depTree - The current dependency tree
   * @protected
   */
	_addDependenciesToSbom(sbom, depTree) {
		const dependencies = {
			...depTree["dependencies"],
			...depTree["optionalDependencies"],
		};

		Object.entries(dependencies)
			.forEach(entry => {
				const [name, artifact] = entry;
				const target = toPurl(purlType, name, artifact.version);
				const rootPurl = toPurl(purlType, this.#manifest.name, this.#manifest.version);
				sbom.addDependency(rootPurl, target, undefined, this._hashesFor(name, artifact.version));
				this.#addDependenciesOf(sbom, target, artifact);
			});
	}

	/**
   * Adds dependencies of a specific package to the SBOM
   * @param {Sbom} sbom - The SBOM object to add dependencies to
   * @param {PackageURL} from - The package URL to add dependencies for
   * @param {Object} artifact - The artifact containing dependencies
   * @private
   */
	#addDependenciesOf(sbom, from, artifact) {
		const deps = artifact.dependencies || {};
		Object.entries(deps)
			.forEach(entry => {
				const [name, depArtifact] = entry;
				if(depArtifact.version !== undefined) {
					const target = toPurl(purlType, name, depArtifact.version);
					sbom.addDependency(from, target, undefined, this._hashesFor(name, depArtifact.version));
					this.#addDependenciesOf(sbom, target, depArtifact);
				}
			});
	}

	/**
   * Creates a SBOM containing only direct dependencies
   * @param {Object} [opts={}] - Optional configuration options
   * @returns {string} The SBOM as a JSON string
   * @private
   */
	#getDirectDependencySbom(opts = {}) {
		const depTree = this._buildDependencyTree(false, opts);
		let mainComponent = toPurl(purlType, this.#manifest.name, this.#manifest.version);
		const license = this.readLicenseFromManifest(this.#manifest.manifestPath);

		let sbom = new Sbom();
		sbom.addRoot(mainComponent, license);

		const rootDeps = this._getRootDependencies(depTree);
		const sortedDepsKeys = Array
			.from(rootDeps.keys())
			.filter(key => this.#manifest.dependencies.includes(key))
			.sort();
		for (const key of sortedDepsKeys) {
			const rootPurl = toPurlFromString(sbom.getRoot().purl);
			const targetPurl = rootDeps.get(key);
			sbom.addDependency(rootPurl, targetPurl, undefined, this._hashesForPurl(targetPurl));
		}
		this.#ensurePeerAndOptionalDeps(sbom);
		sbom.filterIgnoredDeps(this.#manifest.ignored);
		return sbom.getAsJsonString(opts);
	}

	/**
   * Extracts root dependencies from the dependency tree
   * @param {Object} depTree - The dependency tree object
   * @returns {Map<string, PackageURL>} Map of dependency names to their PackageURL objects
   * @protected
   */
	_getRootDependencies(depTree) {
		const allDeps = {
			...depTree.dependencies,
			...depTree.optionalDependencies,
		};
		if (Object.keys(allDeps).length === 0) {
			return new Map();
		}

		return new Map(
			Object.entries(allDeps).map(
				([key, value]) => [key, toPurl(purlType, key, value.version)]
			)
		);
	}

	/**
   * Executes the list command to get dependencies
   * @param {boolean} includeTransitive - Whether to include transitive dependencies
   * @param {string} manifestDir - The manifest directory
   * @returns {string} The command output
   * @private
   */
	#executeListCmd(includeTransitive, manifestDir) {
		const listArgs = this._listCmdArgs(includeTransitive, manifestDir);
		return this.#invokeCommand(listArgs, { cwd: manifestDir });
	}

	/**
   * Gets the version of the package manager
   * @returns {string} The version string of the package manager
   * @protected
   */
	_version() {
		return this.#invokeCommand(['--version']);
	}

	/**
   * Creates or updates the lock file for the package manager
   * @param {string} manifestDir - Directory containing the manifest file
   * @protected
   */
	_createLockFile(manifestDir) {
		const originalDir = process.cwd();
		const isWindows = os.platform() === 'win32';

		if (isWindows) {
			process.chdir(manifestDir);
		}

		try {
			const args = this._updateLockFileCmdArgs(manifestDir);
			this.#invokeCommand(args, { cwd: manifestDir });
		} finally {
			if (isWindows) {
				process.chdir(originalDir);
			}
		}
	}

	/**
   * Invokes a command with the given arguments
   * @param {string[]} args - Command arguments
   * @param {Object} [opts={}] - Optional configuration options
   * @returns {string} Command output
   * @throws {Error} If command execution fails or command is not found
   * @private
   */
	#invokeCommand(args, opts = {}) {
		try {
			if(!opts.cwd) {
				opts.cwd = path.dirname(this.#manifest.manifestPath);
			}

			// Add version manager paths for JavaScript package managers
			if (process.platform !== 'win32') {
				const versionManagerPaths = [];

				// Add fnm path if available
				const fnmDir = getCustom('FNM_DIR', null, opts);
				if (fnmDir) {
					versionManagerPaths.push(`${fnmDir}/current/bin`);
				}

				// Add nvm path if available
				const nvmDir = getCustom('NVM_DIR', null, opts);
				if (nvmDir) {
					versionManagerPaths.push(`${nvmDir}/current/bin`);
				}

				// Add local node_modules/.bin path
				const localBinPath = path.join(opts.cwd, 'node_modules', '.bin');
				if (fs.existsSync(localBinPath)) {
					versionManagerPaths.push(localBinPath);
				}

				if (versionManagerPaths.length > 0) {
					opts = {
						...opts,
						env: {
							...opts.env,
							PATH: `${versionManagerPaths.join(path.delimiter)}${path.delimiter}${process.env.PATH}`
						}
					};
				}
			}

			// Try to find the command in the following order:
			// 1. Custom path from environment/opts (via getCustomPath)
			// 2. Local node_modules/.bin
			// 3. Global installation
			let cmd = this.#cmd;
			if (!fs.existsSync(cmd)) {
				const localCmd = path.join(opts.cwd, 'node_modules', '.bin', this._cmdName());
				if (fs.existsSync(localCmd)) {
					cmd = localCmd;
				}
			}

			return invokeCommand(cmd, args, opts);
		} catch (error) {
			if (error.code === 'ENOENT') {
				throw new Error(`${this.#cmd} is not accessible. Please ensure it is installed via npm, corepack, or your version manager.`);
			}
			if (error.code === 'EACCES') {
				throw new Error(`Permission denied when executing ${this.#cmd}. Please check file permissions.`);
			}
			throw new Error(`Failed to execute ${this.#cmd} ${args.join(' ')}`, { cause: error });
		}
	}

	/**
   * Parses the dependency tree output
   * @param {string} output - The output to parse
   * @returns {string} The parsed output
   * @protected
   */
	_parseDepTreeOutput(output) {
		return output;
	}
}

