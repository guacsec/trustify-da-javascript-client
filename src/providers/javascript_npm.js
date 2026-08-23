import fs from 'node:fs';
import path from 'node:path';

import Base_javascript, { sriToHash } from './base_javascript.js';

export default class Javascript_npm extends Base_javascript {

	_lockFileName() {
		return "package-lock.json";
	}

	/**
	 * Parses `package-lock.json` (lockfileVersion 2/3) into a hash map keyed by
	 * `name@version`. Each `packages` entry is keyed by its install path
	 * (e.g. `node_modules/@hapi/joi`); the package name is the segment after the
	 * final `node_modules/`. The `integrity` field holds an SRI string.
	 * @param {string} lockDir - Directory containing package-lock.json
	 * @returns {Map<string, Array<{alg: string, content: string}>>} Hash map
	 * @protected
	 */
	_parseLockFileHashes(lockDir) {
		const map = new Map();
		const lockPath = path.join(lockDir, this._lockFileName());
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
			const name = idx < 0 ? pkgPath : pkgPath.slice(idx + marker.length);
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

	_listCmdArgs(includeTransitive) {
		return ['ls', includeTransitive ? '--all' : '--depth=0', '--package-lock-only', '--omit=dev', '--json'];
	}

	_updateLockFileCmdArgs() {
		return ['install', '--package-lock-only'];
	}

	_buildDependencyTree(includeTransitive, opts = {}) {
		// npm ls --json returns a single tree rooted at the workspace root.
		// When analyzing a workspace member, its deps are nested under the
		// root's dependencies keyed by the member name — extract that subtree
		// so downstream analysis sees only the member's dependencies.
		const tree = super._buildDependencyTree(includeTransitive, opts);
		const memberName = this._getManifest().name;
		if (tree.name === memberName) {
			return tree;
		}
		const memberEntry = tree.dependencies?.[memberName];
		if (memberEntry) {
			return {
				name: memberName,
				version: memberEntry.version || this._getManifest().version,
				dependencies: memberEntry.dependencies,
				optionalDependencies: memberEntry.optionalDependencies,
			};
		}
		return tree;
	}
}
