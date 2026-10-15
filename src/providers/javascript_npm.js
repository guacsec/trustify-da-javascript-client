import fs from 'node:fs';
import path from 'node:path';

import Base_javascript, { sriToHash } from './base_javascript.js';
import { readNpmGraph } from './javascript_lockfile.js';

export default class Javascript_npm extends Base_javascript {

	_lockFileName() {
		return "package-lock.json";
	}

	/**
	 * Parses `package-lock.json` (lockfileVersion 2/3) into a hash map keyed by
	 * `name@version`. Each `packages` entry is keyed by its install path
	 * (e.g. `node_modules/@hapi/joi`). The package name comes from `entry.name`,
	 * falling back to the install path after the final `node_modules/` when present.
	 * The `integrity` field holds an SRI string.
	 * @param {string} lockDir - Directory containing package-lock.json
	 * @returns {Map<string, Array<{alg: string, content: string}>>} Hash map
	 * @protected
	 */
	_parseLockFileHashes(lockDir) {
		const map = new Map();
		const lockPath = path.join(lockDir, this._lockFileNames().find(name => fs.existsSync(path.join(lockDir, name))) || this._lockFileName());
		if (!fs.existsSync(lockPath)) {
			return map;
		}
		let lock;
		try {
			lock = JSON.parse(fs.readFileSync(lockPath, 'utf-8'));
		} catch (_) {
			return map;
		}
		const packages = lock.packages || {};
		for (const [pkgPath, entry] of Object.entries(packages)) {
			if (!pkgPath || !entry || !entry.integrity || !entry.version) {
				continue;
			}
			const marker = 'node_modules/';
			const idx = pkgPath.lastIndexOf(marker);
			const name = entry.name || (idx < 0 ? pkgPath : pkgPath.slice(idx + marker.length));
			const hash = sriToHash(entry.integrity);
			if (name && hash) {
				map.set(`${name}@${entry.version}`, [hash]);
			}
		}
		return map;
	}

	_cmdName() {
		return "npm";
	}

	_lockFileNames() {
		return ['npm-shrinkwrap.json', this._lockFileName()];
	}

	_setUp(manifestPath) {
		this._setUpManifest(manifestPath);
	}

	_buildDependencyTree(_includeTransitive, opts = {}) {
		const manifest = this._getManifest();
		const lockDir = this._findLockFileDir(path.dirname(manifest.manifestPath), opts);
		if (!lockDir) {
			throw new Error('npm analysis requires a lockfile. Generate package-lock.json before scanning.');
		}
		const graph = readNpmGraph(lockDir, manifest.manifestPath, manifest.content);
		this._loadHashes(lockDir);
		return graph;
	}
}
