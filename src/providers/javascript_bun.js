import fs from 'node:fs'
import path from 'node:path'

import Base_javascript, { sriToHash } from './base_javascript.js';
import { parseBunEntry, readBunGraph, readBunLock } from './javascript_lockfile.js';

export default class Javascript_bun extends Base_javascript {

	_lockFileName() {
		return "bun.lock";
	}

	_cmdName() {
		return "bun";
	}

	/** Initializes the provider without resolving the bun executable. */
	_setUp(manifestPath) {
		this._setUpManifest(manifestPath);
	}

	/**
	 * Parses `bun.lock` into a hash map keyed by `name@version`. Each entry in the
	 * `packages` section is a tuple whose resolved id (`name@version`) and trailing
	 * integrity string are extracted by {@link parseBunEntry}, so npm, hosted/git
	 * and empty-registry entries are all handled.
	 * @param {string} lockDir - Directory containing bun.lock
	 * @returns {Map<string, Array<{alg: string, content: string}>>} Hash map
	 * @protected
	 */
	_parseLockFileHashes(lockDir) {
		const map = new Map();
		const lockPath = path.join(lockDir, this._lockFileName());
		if (!fs.existsSync(lockPath)) {
			return map;
		}
		let lockData;
		try {
			lockData = readBunLock(lockPath);
		} catch (_) {
			return map;
		}
		const packages = lockData?.packages || {};
		for (const entry of Object.values(packages)) {
			if (!Array.isArray(entry) || typeof entry[0] !== 'string') {
				continue;
			}
			const { name, version, integrity } = parseBunEntry(entry);
			const hash = integrity ? sriToHash(integrity) : null;
			if (name && version && hash) {
				map.set(`${name}@${version}`, [hash]);
			}
		}
		return map;
	}

	/**
	 * Builds the dependency graph directly from `bun.lock`, requiring a
	 * pre-existing text lockfile and invoking no package manager. A binary
	 * `bun.lockb` without a text `bun.lock` is rejected with a migrate diagnostic.
	 * @param {boolean} _includeTransitive - Unused; the full graph is always read
	 * @param {Object} [opts={}] - Configuration options (may set the workspace dir)
	 * @returns {import('./javascript_lockfile.js').LockGraph} The dependency graph
	 * @protected
	 */
	_buildDependencyTree(_includeTransitive, opts = {}) {
		const manifest = this._getManifest();
		const manifestDir = path.dirname(manifest.manifestPath);
		const lockDir = this._findLockFileDir(manifestDir, opts);
		if (!lockDir) {
			if (this.#binaryLockFileDir(manifestDir)) {
				throw new Error("Bun analysis found a binary 'bun.lockb' but no text 'bun.lock'. Migrate it with 'bun install --save-text-lockfile' (Bun >= 1.2) before scanning.");
			}
			throw new Error('Bun analysis requires a lockfile. Generate bun.lock before scanning.');
		}
		const lock = readBunLock(path.join(lockDir, this._lockFileName()));
		const graph = readBunGraph(lockDir, manifest.manifestPath, manifest.content, lock);
		this._loadHashes(lockDir);
		return graph;
	}

	/**
	 * Walks up from the manifest directory looking for a binary `bun.lockb`,
	 * stopping at the workspace root, to drive an actionable migrate diagnostic.
	 * @param {string} manifestDir - Directory containing the manifest file
	 * @returns {string|null} The directory containing bun.lockb, or null
	 * @private
	 */
	#binaryLockFileDir(manifestDir) {
		let dir = path.resolve(manifestDir);
		while (true) {
			if (fs.existsSync(path.join(dir, 'bun.lockb'))) {
				return dir;
			}
			if (this._isWorkspaceRoot(dir)) {
				return null;
			}
			const parent = path.dirname(dir);
			if (parent === dir) {
				return null;
			}
			dir = parent;
		}
	}
}
