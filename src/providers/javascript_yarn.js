import fs from 'node:fs';
import path from 'node:path';

import { parseSyml } from '@yarnpkg/parsers';

import { environmentVariableIsPopulated } from '../tools.js';

import Base_javascript, { sriToHash } from './base_javascript.js';
import Manifest from './manifest.js';
import Yarn_berry_processor from './processors/yarn_berry_processor.js';
import Yarn_classic_processor from './processors/yarn_classic_processor.js';

/**
 * Converts a Yarn Berry `checksum` value to a CycloneDX hash object. Berry
 * checksums are formatted as `<cacheKey>/<hex-sha512>`; the digest is the
 * hex-encoded SHA-512 following the final slash.
 * @param {string} checksum - The checksum field value
 * @returns {{alg: string, content: string}|null} CycloneDX hash, or null
 */
function berryChecksumToHash(checksum) {
	if (typeof checksum !== 'string') {
		return null;
	}
	const slash = checksum.lastIndexOf('/');
	const hex = (slash >= 0 ? checksum.slice(slash + 1) : checksum).trim();
	if (!/^[0-9a-f]+$/i.test(hex)) {
		return null;
	}
	return { alg: 'SHA-512', content: hex.toLowerCase() };
}

export default class Javascript_yarn extends Base_javascript {

	static VERSION_PATTERN = /^([0-9]+)\./;

	#processor;

	_lockFileName() {
		return "yarn.lock";
	}

	/**
	 * Parses `yarn.lock` into a hash map keyed by `name@version`. Supports both
	 * Yarn Classic (v1) entries with an `integrity` SRI field and Yarn Berry
	 * (v2+) entries with a `checksum` field.
	 * @param {string} lockDir - Directory containing yarn.lock
	 * @returns {Map<string, Array<{alg: string, content: string}>>} Hash map
	 * @protected
	 */
	_parseLockFileHashes(lockDir) {
		const map = new Map();
		const lockPath = path.join(lockDir, this._lockFileName());
		if (!fs.existsSync(lockPath)) {
			return map;
		}
		let content;
		try {
			content = fs.readFileSync(lockPath, 'utf-8');
		} catch (_) {
			return map;
		}

		const parsed = parseSyml(content);

		for (const [spec, entry] of Object.entries(parsed)) {
			if (spec === '__metadata') {
				continue;
			}

			const version = entry.version;
			if (!version) {
				continue;
			}

			let hash = null;
			if (entry.integrity) {
				hash = sriToHash(entry.integrity);
			} else if (entry.checksum) {
				hash = berryChecksumToHash(entry.checksum);
			}

			if (!hash) {
				continue;
			}

			// Handle comma-separated specifiers (e.g., "pkg@^1.0.0, pkg@^2.0.0")
			for (const rawSpec of spec.split(',')) {
				const trimmed = rawSpec.trim();
				const atIndex = trimmed.lastIndexOf('@');
				if (atIndex > 0) {
					const name = trimmed.slice(0, atIndex);
					map.set(`${name}@${version}`, [hash]);
				}
			}
		}

		return map;
	}

	_cmdName() {
		return "yarn";
	}

	_listCmdArgs(includeTransitive, manifestDir) {
		return this.#processor.listCmdArgs(includeTransitive, manifestDir);
	}

	_updateLockFileCmdArgs(manifestDir) {
		return this.#processor.updateLockFileCmdArgs(manifestDir);
	}

	_setUp(manifestPath, opts) {
		const manifest = new Manifest(manifestPath);
		// Auto-detect Yarn variant only if TRUSTIFY_DA_YARN_PATH is not explicitly set
		const yarnPathKey = 'TRUSTIFY_DA_YARN_PATH';
		// An empty opts/env value is treated as unset so auto-detection still runs
		// (getCustomPath would otherwise reject the empty path).
		const hasExplicitPath = (typeof opts[yarnPathKey] === 'string' && opts[yarnPathKey] !== '') ||
			environmentVariableIsPopulated(yarnPathKey);
		const resolvedOpts = { ...opts };

		if (!hasExplicitPath) {
			const autoPath = this._detectYarnPath(manifestPath, opts, manifest);
			if (autoPath) {
				resolvedOpts[yarnPathKey] = fs.existsSync(autoPath) ? autoPath : this._cmdName();
			}
		}

		super._setUp(manifestPath, resolvedOpts, manifest);

		const versionDir = this._findLockFileDir(path.dirname(manifestPath), opts) || path.dirname(manifestPath);
		const version = this._version({ cwd: versionDir }) ?? '';
		const matches = Javascript_yarn.VERSION_PATTERN.exec(version);

		if (matches?.length !== 2) {
			throw new Error(`Invalid Yarn version format: ${version}`);
		}

		const isClassic = matches[1] === '1';
		this._setEcosystem(isClassic ? 'yarn-classic' : 'yarn-berry');
		this.#processor = isClassic ? new Yarn_classic_processor(this._getManifest()) : new Yarn_berry_processor(this._getManifest());
	}

	/**
	 * Detects the correct Yarn binary path based on project manifest signals.
	 * Uses the same workspace lock file lookup as dependency analysis.
	 * Uses the container's Corepack shim for project declarations, falling back to PATH during setup.
	 * Otherwise checks .yarnrc.yml and the lockfile format before defaulting to Classic.
	 * @param {string} manifestPath - Path to package.json
	 * @param {Object} [opts={}] - Options, including TRUSTIFY_DA_WORKSPACE_DIR
	 * @param {Manifest} [manifest] - Manifest already loaded during setup
	 * @returns {string|null} Yarn command name or absolute binary path, or null if not a Yarn project
	 * @private
	 */
	_detectYarnPath(manifestPath, opts = {}, manifest) {
		const manifestName = path.basename(manifestPath);

		// Only detect for Yarn projects (package.json + a reachable yarn.lock)
		if (manifestName !== 'package.json') {
			return null;
		}
		const manifestDir = this._findLockFileDir(path.dirname(manifestPath), opts);
		if (!manifestDir) {
			return null;
		}

		// Let Corepack resolve project declarations instead of forcing a bundled version.
		try {
			const rootManifestPath = path.join(manifestDir, 'package.json');
			const rootManifest = manifest && path.resolve(manifest.manifestPath) === rootManifestPath
				? manifest
				: JSON.parse(fs.readFileSync(rootManifestPath, 'utf-8'));
			const packageManager = rootManifest.packageManager;
			const devPackageManager = rootManifest.devEngines?.packageManager;

			// The top-level declaration takes precedence; non-Yarn declarations prevent guessing.
			if (packageManager != null || devPackageManager != null) {
				const isYarn = packageManager != null
					? typeof packageManager === 'string' && packageManager.startsWith('yarn@')
					: devPackageManager.name === 'yarn';
				// An absolute shim prevents node_modules/.bin/yarn from shadowing Corepack.
				return isYarn ? '/usr/local/corepack/bin/yarn' : null;
			}
		} catch (err) {
			// If we can't read package.json, fall through to file-based detection
		}

		// Berry's rc file is optional; its lockfile contains a __metadata entry.
		const yarnrcPath = path.join(manifestDir, '.yarnrc.yml');
		if (fs.existsSync(yarnrcPath) ||
			parseSyml(fs.readFileSync(path.join(manifestDir, this._lockFileName()), 'utf-8')).__metadata) {
			return '/usr/local/bin/yarn-berry';
		}

		// Default to Classic for bare v1 yarn.lock
		return '/usr/local/bin/yarn-classic';
	}

	_getRootDependencies(depTree) {
		return this.#processor.getRootDependencies(depTree);
	}

	_parseDepTreeOutput(output) {
		return this.#processor.parseDepTreeOutput(output);
	}

	_addDependenciesToSbom(sbom, depTree) {
		this.#processor.addDependenciesToSbom(sbom, depTree, purl => this._hashesForPurl(purl));
	}

}
