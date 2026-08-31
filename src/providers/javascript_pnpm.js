import fs from 'node:fs';
import path from 'node:path';

import { load as yamlLoad } from 'js-yaml';

import Base_javascript, { sriToHash } from './base_javascript.js';

export default class Javascript_pnpm extends Base_javascript {

	_lockFileName() {
		return "pnpm-lock.yaml";
	}

	/**
	 * Parses `pnpm-lock.yaml` (lockfileVersion 9) into a hash map keyed by
	 * `name@version`. Entries in the `packages` section are keyed by
	 * `<name>@<version>` (optionally followed by a `(peer@x)` suffix); the
	 * `resolution.integrity` field holds an SRI string.
	 * @param {string} lockDir - Directory containing pnpm-lock.yaml
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
			lock = yamlLoad(fs.readFileSync(lockPath, 'utf-8'));
		} catch (_) {
			return map;
		}
		const packages = lock?.packages || {};
		for (const [key, entry] of Object.entries(packages)) {
			const integrity = entry?.resolution?.integrity;
			if (!key || !integrity) {
				continue;
			}
			// Strip any peer-dependency suffix, then split name from version
			const base = key.split('(')[0];
			const at = base.lastIndexOf('@');
			if (at <= 0) {
				continue;
			}
			const name = base.slice(0, at);
			const version = base.slice(at + 1);
			const hash = sriToHash(integrity);
			if (name && version && hash) {
				map.set(`${name}@${version}`, [hash]);
			}
		}
		return map;
	}

	_cmdName() {
		return "pnpm";
	}

	_listCmdArgs(includeTransitive) {
		return ['ls', includeTransitive ? '--depth=Infinity' : '--depth=0', '--prod', '--json', '-r'];
	}

	_updateLockFileCmdArgs() {
		return ['install', '--frozen-lockfile'];
	}

	_buildDependencyTree(includeTransitive, opts = {}) {
		// pnpm ls --json returns an array with one entry per workspace package.
		// When analyzing a workspace member, find its entry by name instead of
		// blindly taking the first element (which is the workspace root).
		const tree = super._buildDependencyTree(includeTransitive, opts);
		if (Array.isArray(tree) && tree.length > 0) {
			const memberName = this._getManifest().name;
			return tree.find(pkg => pkg.name === memberName) || tree[0];
		}
		return {};
	}

}
