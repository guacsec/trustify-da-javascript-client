import fs from 'node:fs';
import path from 'node:path';

import Base_javascript, { sriToHash } from './base_javascript.js';
import { berryChecksumToHash, readYarnGraph, readYarnLock } from './javascript_lockfile.js';

export default class Javascript_yarn extends Base_javascript {
	#lock;
	#lockDir;

	_lockFileName() {
		return 'yarn.lock';
	}

	_cmdName() {
		return 'yarn';
	}

	_setUp(manifestPath, opts) {
		this._setUpManifest(manifestPath);
		this.#lockDir = this._findLockFileDir(path.dirname(manifestPath), opts);
		if (!this.#lockDir) {
			throw new Error('Yarn analysis requires a lockfile. Generate yarn.lock before scanning.');
		}
		this.#lock = readYarnLock(path.join(this.#lockDir, this._lockFileName()));
		this._setEcosystem(this.#lock.__metadata != null ? 'yarn-berry' : 'yarn-classic');
	}

	_buildDependencyTree() {
		const manifest = this._getManifest();
		const graph = readYarnGraph(this.#lockDir, manifest.manifestPath, manifest.content, this.#lock);
		this._loadHashes(this.#lockDir);
		return graph;
	}

	_parseLockFileHashes(lockDir) {
		const file = path.join(lockDir, this._lockFileName());
		const map = new Map();
		if (!fs.existsSync(file)) { return map; }
		const lock = lockDir === this.#lockDir ? this.#lock : readYarnLock(file);
		for (const [selectors, entry] of Object.entries(lock)) {
			if (selectors === '__metadata') { continue; }
			const hash = entry.integrity ? sriToHash(entry.integrity) : berryChecksumToHash(entry.checksum);
			if (!hash || !entry.version) { continue; }
			const spec = entry.resolution || selectors.split(',')[0];
			const identity = !entry.resolution && spec.includes('@npm:') ? spec.slice(spec.indexOf('@npm:') + 5) : spec;
			const name = /^(@[^/]+\/[^@]+|[^@]+)@/.exec(identity)?.[1];
			if (name) { map.set(`${name}@${entry.version}`, [hash]); }
		}
		return map;
	}
}
