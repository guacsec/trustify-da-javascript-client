import fs from 'node:fs';
import path from 'node:path';

import { parseSyml } from '@yarnpkg/parsers';

import Base_javascript, { sriToHash } from './base_javascript.js';
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
		super._setUp(manifestPath, opts);

		const version = this._version() ?? '';
		const matches = Javascript_yarn.VERSION_PATTERN.exec(version);

		if (matches?.length !== 2) {
			throw new Error(`Invalid Yarn version format: ${version}`);
		}

		const isClassic = matches[1] === '1';
		this._setEcosystem(isClassic ? 'yarn-classic' : 'yarn-berry');
		this.#processor = isClassic ? new Yarn_classic_processor(this._getManifest()) : new Yarn_berry_processor(this._getManifest());
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
