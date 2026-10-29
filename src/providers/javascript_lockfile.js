import fs from 'node:fs';
import path from 'node:path';
import { isDeepStrictEqual } from 'node:util';

import { parseResolution, parseSyml } from '@yarnpkg/parsers';
import glob from 'fast-glob';
import { load as yamlLoad, loadAll as yamlLoadAll } from 'js-yaml';
import { parse as parseJsonc } from 'jsonc-parser';
import micromatch from 'micromatch';
import semver from 'semver';

import { toPurl, toPurlFromString } from '../tools.js';

import { sriToHash } from './base_javascript.js';

/** @typedef {{name: string, version: string, dependencies: Map<string, string>, hashes?: Array<{alg: string, content: string}>}} LockNode */
/** @typedef {{rootId: string, nodes: Map<string, LockNode>}} LockGraph */

function object(value) {
	return value != null && typeof value === 'object' && !Array.isArray(value);
}

function enabled(value) {
	return value === true || value === 'true';
}

function readJson(file) {
	try {
		const data = JSON.parse(fs.readFileSync(file, 'utf8'));
		if (!object(data)) { throw new Error('expected an object'); }
		return data;
	} catch (cause) {
		throw new Error(`Cannot read ${file}: ${cause.message}`, { cause });
	}
}

function dependencyMap(data, field, file) {
	const value = data[field] ?? {};
	if (!object(value) || Object.values(value).some(spec => typeof spec !== 'string' || !spec)) {
		throw new Error(`Invalid ${field} in ${file}: expected dependency names and string specifications.`);
	}
	return value;
}

function stale(file, dependency, detail) {
	throw new Error(`Lockfile is out of date for ${file}: ${dependency} ${detail}. Synchronize the project with its package manager before scanning.`);
}

function unsupported(file, dependency, detail) {
	throw new Error(`Unsupported lockfile metadata in ${file} for ${dependency}: ${detail}. No dependency analysis was produced.`);
}

function manifestDependencies(data, file, includeDev = false) {
	return {
		...(includeDev ? dependencyMap(data, 'devDependencies', file) : {}),
		...dependencyMap(data, 'dependencies', file),
		...dependencyMap(data, 'optionalDependencies', file),
	};
}

function projectManifests(root, selected, data) {
	const selectedPath = path.resolve(selected);
	const rootPath = path.join(root, 'package.json');
	const manifests = new Map([[selectedPath, data]]);
	const rootData = selectedPath === rootPath ? data : readJson(rootPath);
	manifests.set(rootPath, rootData);
	const workspaces = Array.isArray(rootData.workspaces) ? rootData.workspaces : rootData.workspaces?.packages;
	if (workspaces != null) {
		if (!Array.isArray(workspaces) || workspaces.some(pattern => typeof pattern !== 'string')) {
			throw new Error(`Invalid workspaces in ${rootPath}.`);
		}
		const files = glob.sync(workspaces.map(pattern => `${pattern}/package.json`), {
			cwd: root, absolute: true, onlyFiles: true,
			ignore: ['**/node_modules/**', '**/.git/**', '**/.yarn/**'],
		});
		for (const file of files) {
			const resolved = path.resolve(file);
			if (!manifests.has(resolved)) { manifests.set(resolved, readJson(resolved)); }
		}
	}
	return manifests;
}

function descriptor(spec) {
	const match = /^(@[^/]+\/[^@]+|[^@]+)@(.+)$/.exec(spec);
	if (!match) { throw new Error(`Invalid lockfile descriptor: ${spec}`); }
	return { name: match[1], range: match[2] };
}

function normalizedYarnRange(range) {
	return /^(?:[a-z][a-z+.-]*:|https?:|git\+|git@)/i.test(range) ? range : `npm:${range}`;
}

function validateRange(file, name, spec, target) {
	let range = spec;
	if (range.startsWith('npm:')) {
		range = range.slice(4);
		if (range.includes('@')) {
			const alias = descriptor(range);
			if (target.name !== alias.name) { stale(file, name, `resolves to ${target.name}, expected ${alias.name}`); }
			range = alias.range;
		}
	}
	if (range.startsWith('workspace:')) {
		range = range.slice(10);
		if (range === '^' || range === '~') { range = '*'; }
	}
	if (semver.validRange(range) && !semver.satisfies(target.version, range)) {
		stale(file, name, `requires ${spec} but resolves to ${target.version}`);
	}
}

function validateSnapshot(file, actual, recorded, fields, normalize = value => value) {
	for (const field of fields) {
		const expected = dependencyMap(actual, field, file);
		const locked = dependencyMap(recorded, field, file);
		for (const name of new Set([...Object.keys(expected), ...Object.keys(locked)])) {
			if (normalize(expected[name]) !== normalize(locked[name])) {
				stale(file, name, `has a different ${field} declaration`);
			}
		}
	}
}

/** Berry checksums describe Yarn cache archives, not registry tarballs. */
export function berryChecksumToHash(checksum) {
	if (typeof checksum !== 'string') { return null; }
	const hex = checksum.slice(checksum.lastIndexOf('/') + 1);
	return /^[0-9a-f]{128}$/i.test(hex) ? { alg: 'SHA-512', content: hex.toLowerCase() } : null;
}

function hashes(entry) {
	const hash = entry.integrity ? sriToHash(entry.integrity) : berryChecksumToHash(entry.checksum);
	return hash ? [hash] : undefined;
}

/** Direct dependencies retain their declared names so aliases are not duplicated. */
export function graphRootDependencies(graph) {
	return new Map([...graph.nodes.get(graph.rootId).dependencies].map(([name, id]) => {
		const node = graph.nodes.get(id);
		return [name, toPurl('npm', node.name, node.version)];
	}));
}

/** Emits each contextual edge once; distinct contexts may share an SBOM PURL. */
export function addGraphToSbom(sbom, graph) {
	const visited = new Set();
	const queue = [graph.rootId];
	for (let i = 0; i < queue.length; i++) {
		const id = queue[i];
		if (visited.has(id)) { continue; }
		visited.add(id);
		const node = graph.nodes.get(id);
		const from = id === graph.rootId ? toPurlFromString(sbom.getRoot().purl) : toPurl('npm', node.name, node.version);
		for (const targetId of node.dependencies.values()) {
			const target = graph.nodes.get(targetId);
			sbom.addDependency(from, toPurl('npm', target.name, target.version), undefined, target.hashes);
			queue.push(targetId);
		}
	}
}

/** Reads npm's recorded installation locations without inspecting node_modules. */
export function readNpmGraph(root, manifestPath, manifest) {
	const file = path.join(root, fs.existsSync(path.join(root, 'npm-shrinkwrap.json')) ? 'npm-shrinkwrap.json' : 'package-lock.json');
	const lock = readJson(file);
	if (![2, 3].includes(lock.lockfileVersion)) {
		throw new Error(`Unsupported npm lockfile version ${lock.lockfileVersion} in ${file}. Regenerate a version 2 or 3 lockfile before scanning.`);
	}
	if (!object(lock.packages) || !object(lock.packages[''])) { unsupported(file, 'packages', 'missing root package table'); }
	const manifests = projectManifests(root, manifestPath, manifest);
	for (const entry of Object.values(lock.packages)) {
		if (entry?.link && typeof entry.resolved === 'string') {
			const manifestFile = path.resolve(root, entry.resolved, 'package.json');
			if (!manifests.has(manifestFile)) { manifests.set(manifestFile, readJson(manifestFile)); }
		}
	}
	const local = new Map();
	for (const [manifestFile, data] of manifests) {
		const location = path.relative(root, path.dirname(manifestFile)).split(path.sep).join('/');
		const entry = lock.packages[location];
		if (!object(entry)) { stale(manifestFile, data.name, 'is missing from the lockfile'); }
		if ((entry.name != null && data.name !== entry.name) || (entry.version != null && data.version !== entry.version)) { stale(manifestFile, data.name, 'has a different locked identity'); }
		validateSnapshot(manifestFile, data, entry, ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']);
		local.set(location, { data, file: manifestFile });
	}
	const rootId = path.relative(root, path.dirname(path.resolve(manifestPath))).split(path.sep).join('/');
	const graph = { rootId, nodes: new Map() };
	const rootData = manifests.get(path.join(root, 'package.json'));
	if (rootData.overrides != null && !object(rootData.overrides)) { unsupported(file, 'overrides', 'expected a mapping'); }
	function target(location, name, peer = false) {
		let dir = path.resolve(root, location);
		if (peer && location.includes('node_modules/')) { dir = path.dirname(dir); }
		while (true) {
			if (path.basename(dir) !== 'node_modules') {
				let id = path.relative(root, path.join(dir, 'node_modules', name)).split(path.sep).join('/');
				const seen = new Set();
				while (lock.packages[id]?.link) {
					if (seen.has(id)) { unsupported(file, name, 'cyclic package links'); }
					seen.add(id);
					id = lock.packages[id].resolved;
					if (typeof id !== 'string') { unsupported(file, name, 'missing link target'); }
				}
				if (object(lock.packages[id])) { return id; }
			}
			const parent = path.dirname(dir);
			if (parent === dir) { return undefined; }
			dir = parent;
		}
	}
	function visit(id, ancestry = []) {
		if (graph.nodes.has(id)) { return; }
		const entry = lock.packages[id];
		if (!object(entry)) { unsupported(file, id, 'missing package metadata'); }
		const identity = local.get(id)?.data ?? entry;
		const name = identity.name || id.slice(id.lastIndexOf('node_modules/') + 13);
		const version = identity.version ?? (local.has(id) ? 'v0.0.0' : undefined);
		if (typeof name !== 'string' || !name || typeof version !== 'string' || !version) { unsupported(file, id, 'missing package name or version'); }
		const node = { name, version, dependencies: new Map(), hashes: hashes(entry) };
		graph.nodes.set(id, node);
		const data = local.get(id)?.data ?? entry;
		const source = local.get(id)?.file ?? file;
		const specs = { ...manifestDependencies(data, source), ...dependencyMap(data, 'peerDependencies', source) };
		if (id === '' && rootId === '') {
			for (const [location, workspace] of local) {
				if (location && !location.startsWith('..') && lock.packages[`node_modules/${workspace.data.name}`]?.link && !Object.hasOwn(specs, workspace.data.name)) {
					specs[workspace.data.name] = workspace.data.version ?? '*';
				}
			}
		}
		for (const [dependency, spec] of Object.entries(specs)) {
			const peer = Object.hasOwn(data.peerDependencies ?? {}, dependency) && !Object.hasOwn(manifestDependencies(data, source), dependency);
			const optional = Object.hasOwn(data.optionalDependencies ?? {}, dependency) || (peer && enabled(data.peerDependenciesMeta?.[dependency]?.optional));
			const childId = target(id, dependency, peer);
			if (childId == null) {
				if (optional || peer) { continue; }
				stale(source, dependency, 'has no locked resolution');
			}
			visit(childId, [...ancestry, node]);
			const child = graph.nodes.get(childId);
			const override = npmOverride(rootData, dependency, spec, ancestry.concat(node), source);
			validateRange(source, dependency, override ?? spec, child);
			node.dependencies.set(dependency, childId);
		}
	}
	for (const [id, localManifest] of local) {
		for (const [name, spec] of Object.entries(manifestDependencies(localManifest.data, localManifest.file, true))) {
			const targetId = target(id, name);
			if (targetId == null) {
				if (Object.hasOwn(localManifest.data.optionalDependencies ?? {}, name)) { continue; }
				stale(localManifest.file, name, 'has no locked resolution');
			}
			const entry = lock.packages[targetId];
			const identity = { ...entry, name: entry.name || name };
			validateRange(localManifest.file, name, npmOverride(rootData, name, spec, [localManifest.data], localManifest.file) ?? spec, identity);
		}
	}
	visit(rootId);
	return graph;
}

function npmOverride(root, name, spec, ancestors, file) {
	const overrides = root.overrides;
	let result;
	function search(rules, chain) {
		if (!object(rules)) { return; }
		for (const [key, value] of Object.entries(rules)) {
			if (key === '.') { continue; }
			const parsed = key.includes('@', 1) ? descriptor(key) : { name: key, range: '*' };
			let range = spec;
			if (range.startsWith('npm:')) {
				range = range.slice(4);
				if (range.includes('@')) { range = descriptor(range).range; }
			}
			if (parsed.name === name && chain.length === 0 && (!semver.validRange(range) || semver.intersects(range, parsed.range))) {
				result ??= object(value) ? value['.'] : value;
			}
			const replacement = object(value) ? value['.'] : value;
			const index = chain.findIndex(node => node.name === parsed.name && (semver.satisfies(node.version, parsed.range) ||
				(typeof replacement === 'string' && semver.validRange(replacement) && semver.satisfies(node.version, replacement))));
			if (index >= 0) { search(value, chain.slice(index + 1)); }
		}
	}
	search(overrides, ancestors);
	search(overrides, []);
	if (typeof result === 'string' && result.startsWith('$')) {
		result = manifestDependencies(root, file, true)[result.slice(1)];
	}
	if (result != null && typeof result !== 'string') { unsupported(file, name, 'invalid override'); }
	return result;
}

/** Reads descriptors and locators without invoking Yarn or loading executable plugins. */
export function readYarnLock(file) {
	let lock;
	try {
		lock = parseSyml(fs.readFileSync(file, 'utf8'));
		if (!object(lock)) { throw new Error('expected a lockfile mapping'); }
	} catch (cause) {
		throw new Error(`Cannot read ${file}: ${cause.message}`, { cause });
	}
	if (lock.__metadata != null && (!object(lock.__metadata) || !/^\d+$/.test(String(lock.__metadata.version)) || Number(lock.__metadata.version) < 2 || Number(lock.__metadata.version) > 10)) {
		unsupported(file, '__metadata', 'unknown Berry lockfile version');
	}
	return lock;
}

export function readYarnGraph(root, manifestPath, manifest, lock) {
	const file = path.join(root, 'yarn.lock');
	const berry = lock.__metadata != null;
	const manifests = projectManifests(root, manifestPath, manifest);
	const rootData = manifests.get(path.join(root, 'package.json'));
	if (rootData.resolutions != null && (!object(rootData.resolutions) || Object.values(rootData.resolutions).some(value => typeof value !== 'string'))) { unsupported(file, 'resolutions', 'expected string specifications'); }
	const resolutions = Object.entries(rootData.resolutions ?? {}).map(([selector, replacement]) => {
		try { return { selector, replacement, pattern: berry ? parseResolution(selector) : undefined }; }
		catch { unsupported(file, selector, 'invalid resolution selector'); }
	});
	const entries = new Map();
	const selectors = new Map();
	const locals = new Map();
	for (const [key, entry] of Object.entries(lock)) {
		if (key === '__metadata') { continue; }
		if (!object(entry) || typeof entry.version !== 'string' || !entry.version || (berry && typeof entry.resolution !== 'string')) { unsupported(file, key, 'missing version or resolution'); }
		const keys = key.split(/,\s+(?=@?[^ ,]+@)/);
		const identity = descriptor(berry ? entry.resolution : keys[0]);
		const name = !berry && identity.range.startsWith('npm:') ? descriptor(identity.range.slice(4)).name : identity.name;
		const id = berry ? entry.resolution : key;
		if (berry && !/^(?:npm:|workspace:|patch:|file:|portal:|link:|https?:|git(?:\+|:)|ssh:)/.test(descriptor(id).range)) {
			unsupported(file, id, 'unknown resolution protocol');
		}
		if (entries.has(id) && JSON.stringify(entries.get(id)) !== JSON.stringify({ ...entry, name })) { unsupported(file, id, 'conflicting package metadata'); }
		entries.set(id, { ...entry, name });
		for (const selector of keys) {
			descriptor(selector);
			if (selectors.has(selector) && selectors.get(selector) !== id) { unsupported(file, selector, 'ambiguous resolutions'); }
			selectors.set(selector, id);
		}
	}
	for (const [manifestFile, data] of manifests) {
		const location = path.relative(root, path.dirname(manifestFile)).split(path.sep).join('/') || '.';
		const id = `${data.name}@workspace:${location}`;
		if (berry) {
			const entry = entries.get(id);
			if (!entry) { stale(manifestFile, data.name, 'has no workspace lockfile entry'); }
			const actual = manifestDependencies(data, manifestFile, true);
			const recorded = dependencyMap(entry, 'dependencies', file);
			for (const name of new Set([...Object.keys(actual), ...Object.keys(recorded)])) {
				if (actual[name] == null || recorded[name] == null || normalizedYarnRange(actual[name]) !== normalizedYarnRange(recorded[name])) {
					stale(manifestFile, name, 'has a different dependency declaration');
				}
			}
			validateSnapshot(manifestFile, data, entry, ['peerDependencies'], value => value == null ? value : normalizedYarnRange(value));
		} else {
			entries.set(id, { name: data.name, version: data.version ?? 'v0.0.0', dependencies: manifestDependencies(data, manifestFile, true) });
		}
		locals.set(id, { data, file: manifestFile });
	}
	for (const [id, entry] of entries) {
		const range = descriptor(berry ? id : id.split(/,\s+/)[0]).range;
		if (!/^(portal:|file:|link:)/.test(range)) { continue; }
		const [reference, parameters] = range.split('::');
		const owner = new URLSearchParams(parameters).get('locator');
		const ownerRange = owner ? descriptor(owner).range : '';
		const origin = ownerRange.startsWith('workspace:') ? path.resolve(root, ownerRange.slice(10)) : root;
		const targetPath = reference.slice(reference.indexOf(':') + 1).split('#')[0];
		const manifestFile = path.resolve(origin, targetPath, 'package.json');
		if (!fs.existsSync(manifestFile)) {
			if (range.startsWith('portal:') || entry.version === '0.0.0-use.local') { unsupported(file, id, 'missing local package manifest'); }
			continue;
		}
		if (range.startsWith('link:')) { unsupported(file, id, 'link protocol does not provide package dependency metadata; use a package-aware local protocol'); }
		const data = readJson(manifestFile);
		if (data.name !== entry.name || (entry.version !== '0.0.0-use.local' && data.version !== entry.version)) { stale(manifestFile, data.name, 'has a different locked identity'); }
		const includeDev = range.startsWith('portal:');
		const actual = manifestDependencies(data, manifestFile, includeDev);
		const recorded = dependencyMap(entry, 'dependencies', file);
		for (const name of new Set([...Object.keys(actual), ...Object.keys(recorded)])) {
			if (actual[name] == null || recorded[name] == null || normalizedYarnRange(actual[name]) !== normalizedYarnRange(recorded[name])) { stale(manifestFile, name, 'has a different dependency declaration'); }
		}
		validateSnapshot(manifestFile, data, entry, ['peerDependencies'], value => value == null ? value : normalizedYarnRange(value));
		locals.set(id, { data, file: manifestFile, includeDev });
	}
	const contextualResolutions = !berry && resolutions.some(({ selector }) => {
		const globalName = selector.replace(/^\*\*\//, '');
		return !/^(?:@[^/]+\/)?[^/@*]+$/.test(globalName);
	});
	const rootId = [...locals].find(([, value]) => value.file === path.resolve(manifestPath))?.[0];
	if (!rootId) { unsupported(file, manifest.name, 'manifest is not in the workspace'); }
	function resolve(name, range, ancestry, source) {
		const owner = ancestry.at(-1);
		const resolution = resolutions.find(({ selector, pattern }) => {
			if (!berry) { return selector === name || micromatch.isMatch([...ancestry.slice(1).map(n => n.name), name].join('/'), selector); }
			return pattern.descriptor.fullName === name && (pattern.descriptor.description == null || normalizedYarnRange(pattern.descriptor.description) === normalizedYarnRange(range)) &&
				(!pattern.from || (pattern.from.fullName === owner?.name && (pattern.from.description == null || normalizedYarnRange(pattern.from.description) === descriptor(owner.locator).range)));
		});
		const effective = resolution?.replacement ?? range;
		const normalized = berry ? normalizedYarnRange(effective) : effective;
		const declared = berry ? normalizedYarnRange(range) : range;
		let id = selectors.get(`${name}@${normalized}`) ?? selectors.get(`${name}@${effective}`) ?? selectors.get(`${name}@${declared}`);
		if (!id && range.startsWith('workspace:')) {
			const loc = [...locals].find(([, value]) => value.data.name === name);
			if (loc) { id = loc[0]; }
		}
		if (!id && !range.includes(':')) {
			const loc = [...locals].find(([, value]) => value.data.name === name && semver.satisfies(value.data.version, range));
			if (loc) { id = loc[0]; }
		}
		if (id) { validateRange(source, name, effective, locals.get(id)?.data ?? entries.get(id)); }
		return id;
	}
	for (const [id, local] of locals) {
		for (const [name, spec] of Object.entries(manifestDependencies(local.data, local.file, local.includeDev !== false))) {
			if (!resolve(name, spec, [{ ...local.data, locator: id }], local.file) && !Object.hasOwn(local.data.optionalDependencies ?? {}, name)) {
				stale(local.file, name, 'has no locked resolution');
			}
		}
		if (!berry) { entries.get(id).peerDependencies = local.data.peerDependencies; }
	}
	const graph = { rootId: '', nodes: new Map() };
	function peerSignature(id, providers, seen = new Set()) {
		if (seen.has(id)) { return [id]; }
		const nextSeen = new Set([...seen, id]);
		const data = locals.get(id)?.data ?? entries.get(id);
		const names = berry ? Object.keys(data?.peerDependencies ?? {}).sort() : [];
		return [id, names.filter(name => providers.has(name)).map(name => [name, peerSignature(providers.get(name), providers, nextSeen)])];
	}
	function visit(id, providers = new Map(), ancestry = []) {
		const entry = entries.get(id);
		const local = locals.get(id);
		const data = local?.data ?? entry;
		const source = local?.file ?? file;
		if (!entry) { unsupported(source, id, 'missing resolution'); }
		const version = data.version ?? (local ? 'v0.0.0' : undefined);
		if (typeof data.name !== 'string' || !data.name || typeof version !== 'string' || !version) { unsupported(source, id, 'missing package identity'); }
		const peers = new Map();
		if (berry) {
			for (const [name, spec] of Object.entries(dependencyMap(data, 'peerDependencies', source))) {
				const peerId = providers.get(name);
				if (peerId) {
					validateRange(source, name, spec, locals.get(peerId)?.data ?? entries.get(peerId));
					peers.set(name, peerId);
				}
			}
		}
		if (contextualResolutions && ancestry.some(node => node.locator === id)) { unsupported(source, id, 'cyclic graph with path-dependent Classic resolutions'); }
		const context = JSON.stringify([peerSignature(id, providers), contextualResolutions ? ancestry.map(node => node.locator) : []]);
		if (graph.nodes.has(context)) { return context; }
		const node = { name: data.name, version, locator: id, dependencies: new Map(), hashes: hashes(entry) };
		graph.nodes.set(context, node);
		const specs = local ? manifestDependencies(data, source, local.includeDev !== false) : { ...dependencyMap(entry, 'dependencies', source), ...dependencyMap(entry, 'optionalDependencies', source) };
		const resolved = new Map();
		for (const [name, spec] of Object.entries(specs)) {
			const target = resolve(name, spec, ancestry.concat(node), source);
			if (!target) {
				const optional = Object.hasOwn(data.optionalDependencies ?? {}, name) || enabled(entry.dependenciesMeta?.[name]?.optional);
				if (optional) { continue; }
				stale(source, name, 'has no locked resolution');
			}
			resolved.set(name, target);
		}
		const provided = new Map([...peers, ...resolved, [node.name, id]]);
		for (const [name, target] of [...resolved, ...peers]) {
			if (local && !Object.hasOwn(manifestDependencies(data, source), name) && !Object.hasOwn(data.peerDependencies ?? {}, name)) { continue; }
			node.dependencies.set(name, peers.has(name) ? visit(target, providers, ancestry) : visit(target, provided, ancestry.concat(node)));
		}
		return context;
	}
	graph.rootId = visit(rootId);
	return graph;
}

/**
 * Reads a `pnpm-lock.yaml` document. pnpm 12+ may emit a multi-document YAML
 * stream; the project graph is always the last document, so a single-document
 * `load` would throw or silently miss it. Returns the parsed lockfile mapping.
 * @param {string} file - Absolute path to pnpm-lock.yaml
 * @returns {Object} The parsed lockfile mapping
 */
export function readPnpmLock(file) {
	let documents;
	try {
		documents = yamlLoadAll(fs.readFileSync(file, 'utf8'));
	} catch (cause) {
		throw new Error(`Cannot read ${file}: ${cause.message}`, { cause });
	}
	const lock = documents.filter(object).at(-1);
	if (!object(lock)) {
		throw new Error(`Cannot read ${file}: expected a lockfile mapping.`);
	}
	return lock;
}

/** Resolves the supported major lockfile version (6 or 9). */
function pnpmLockMajor(lock, file) {
	const major = parseInt(String(lock.lockfileVersion), 10);
	if (![6, 9].includes(major)) {
		throw new Error(`Unsupported pnpm lockfile version ${lock.lockfileVersion} in ${file}. Regenerate a version 6 or 9 lockfile before scanning.`);
	}
	return major;
}

/** Extracts a `{name: specifier}` map from a pnpm importer dependency group. */
function pnpmSpecifiers(group, file) {
	const out = {};
	if (group == null) { return out; }
	if (!object(group)) { unsupported(file, 'importers', 'expected a dependency mapping'); }
	for (const [name, entry] of Object.entries(group)) {
		const specifier = typeof entry === 'string' ? entry : entry?.specifier;
		if (typeof specifier !== 'string' || !specifier) { unsupported(file, name, 'missing dependency specifier'); }
		out[name] = specifier;
	}
	return out;
}

/** Reads root overrides and matches pnpm's parent and dependency selectors. */
function pnpmOverrides(root, rootData, lock, file) {
	const rootFile = path.join(root, 'package.json');
	const workspaceFile = path.join(root, 'pnpm-workspace.yaml');
	const workspace = fs.existsSync(workspaceFile) ? yamlLoad(fs.readFileSync(workspaceFile, 'utf8'), { filename: workspaceFile }) ?? {} : {};
	if (!object(workspace)) { unsupported(workspaceFile, 'overrides', 'expected a workspace mapping'); }
	const manifestOverrides = { ...dependencyMap(rootData, 'resolutions', rootFile), ...dependencyMap(rootData.pnpm ?? {}, 'overrides', rootFile) };
	const configured = Object.keys(manifestOverrides).length ? manifestOverrides : dependencyMap(workspace, 'overrides', workspaceFile);
	const resolved = {};
	const selector = value => value.includes('@', 1) ? descriptor(value) : { name: value, range: undefined };
	const rules = Object.entries(configured).map(([key, value]) => {
		// Split parent>dependency selectors without mistaking a version range's > for the separator.
		const delimiter = key.search(/[^ |@]>/) + 1;
		const target = selector(delimiter ? key.slice(delimiter + 1) : key);
		const parent = delimiter ? selector(key.slice(0, delimiter)) : undefined;
		// pnpm records the values of dependency references and catalogs, not their reference syntax.
		if (value.startsWith('$')) { value = manifestDependencies(rootData, rootFile, true)[value.slice(1)]; }
		if (value?.startsWith('catalog:')) {
			const catalog = value.slice(8) ? workspace.catalogs?.[value.slice(8)] : workspace.catalog;
			value = dependencyMap({ dependencies: catalog }, 'dependencies', workspaceFile)[target.name];
		}
		if (typeof value !== 'string' || !value) { unsupported(rootFile, key, 'cannot resolve override'); }
		resolved[key] = value;
		return { parent, target, value };
	});
	// Different overrides mean the locked versions were selected under different resolution rules.
	if (!isDeepStrictEqual(resolved, lock.overrides ?? {})) { stale(file, 'overrides', 'have different declarations'); }
	const intersects = (range, spec) => !range || range === spec || (semver.validRange(range) && semver.validRange(spec) && semver.intersects(range, spec));
	return (data, manifestFile, name, spec) => {
		let matches = rules.filter(rule => rule.target.name === name && intersects(rule.target.range, spec) &&
			(!rule.parent || (rule.parent.name === data.name && (!rule.parent.range || semver.satisfies(data.version, rule.parent.range)))));
		// Parent-qualified rules take precedence over dependency-only rules.
		const parentMatches = matches.filter(rule => rule.parent);
		if (parentMatches.length) { matches = parentMatches; }
		// pnpm applies the last matching override in declaration order; rules (and the
		// filtered matches) preserve that order, so take the last match directly.
		const value = matches.at(-1)?.value;
		// Local override paths start at the workspace root; importer specifiers start at their manifest.
		const local = /^(file:|link:)(.*)$/.exec(value ?? '');
		return local && !path.isAbsolute(local[2])
			? `${local[1]}${path.relative(path.dirname(manifestFile), path.resolve(root, local[2])).split(path.sep).join('/')}`
			: value;
	};
}

/** Validates manifest declarations against pnpm's importer (the project's lockfile entry). */
function validatePnpmImporter(manifestFile, data, importer, file, override) {
	// pnpm can auto-install peers as dependencies, so compare declarations across all sections.
	const declared = {
		...dependencyMap(data, 'peerDependencies', manifestFile),
		...dependencyMap(data, 'devDependencies', manifestFile),
		...dependencyMap(data, 'dependencies', manifestFile),
		...dependencyMap(data, 'optionalDependencies', manifestFile),
	};
	const recorded = {
		...pnpmSpecifiers(importer.dependencies, file),
		...pnpmSpecifiers(importer.devDependencies, file),
		...pnpmSpecifiers(importer.optionalDependencies, file),
	};
	for (const [name, specifier] of Object.entries(recorded)) {
		if (declared[name] != null && (override(data, manifestFile, name, declared[name]) ?? declared[name]) !== specifier) {
			// The lockfile was generated from a different dependency declaration, including any override.
			stale(manifestFile, name, 'has a different dependency declaration');
		}
	}
	for (const section of ['dependencies', 'devDependencies']) {
		for (const [name, spec] of Object.entries(dependencyMap(data, section, manifestFile))) {
			// Optional declarations override production declarations, which override development declarations.
			if (Object.hasOwn(data.optionalDependencies ?? {}, name) ||
				(section === 'devDependencies' && Object.hasOwn(data.dependencies ?? {}, name))) { continue; }
			// A '-' override removes the dependency, so pnpm need not record it.
			if (override(data, manifestFile, name, spec) === '-') { continue; }
			// Missing or moved required dependencies need a lockfile update.
			if (!Object.hasOwn(importer[section] ?? {}, name)) { stale(manifestFile, name, `has a different ${section} declaration`); }
		}
	}
}

/**
 * Reads pnpm's resolved graph from `pnpm-lock.yaml` without invoking pnpm.
 * Supports lockfileVersion 6 (packages keyed by `/name@version` with inline
 * dependencies) and 9 (packages keyed by `name@version` for integrity, with a
 * separate `snapshots` section keyed by `name@version(peer-context)` holding
 * dependency edges). Peer contexts are preserved in node identity, workspace
 * `link:` edges resolve to importers, and `file:`/`portal:` directory packages
 * resolve through their local manifest.
 * @param {string} root - Workspace root (directory holding pnpm-lock.yaml)
 * @param {string} manifestPath - Path to the analyzed package.json
 * @param {Object} manifest - Parsed package.json content
 * @param {Object} lock - Parsed lockfile (see {@link readPnpmLock})
 * @returns {LockGraph} The resolved dependency graph
 */
export function readPnpmGraph(root, manifestPath, manifest, lock) {
	const file = path.join(root, 'pnpm-lock.yaml');
	const major = pnpmLockMajor(lock, file);
	const prefix = major === 6 ? '/' : '';
	const packages = object(lock.packages) ? lock.packages : {};
	const snapshots = major === 6 ? packages : (object(lock.snapshots) ? lock.snapshots : {});
	const importers = object(lock.importers) ? lock.importers
		: { '.': { dependencies: lock.dependencies, devDependencies: lock.devDependencies, optionalDependencies: lock.optionalDependencies } };

	const manifests = projectManifests(root, manifestPath, manifest);
	const override = pnpmOverrides(root, manifests.get(path.join(root, 'package.json')), lock, file);
	const locals = new Map();
	for (const [manifestFile, data] of manifests) {
		const location = path.relative(root, path.dirname(manifestFile)).split(path.sep).join('/') || '.';
		const importer = importers[location];
		// Without an importer, the lockfile has no dependency declarations for this project.
		if (!object(importer)) { stale(manifestFile, data.name, 'is missing from the lockfile'); }
		validatePnpmImporter(manifestFile, data, importer, file, override);
		locals.set(location, { data, file: manifestFile });
	}

	const rootId = path.relative(root, path.dirname(path.resolve(manifestPath))).split(path.sep).join('/') || '.';
	if (!locals.has(rootId)) { unsupported(file, manifest.name, 'manifest is not in the workspace'); }

	const graph = { rootId: `importer:${rootId}`, nodes: new Map() };

	// Aliases carry a full `name@version` reference in their version field;
	// registry packages carry a bare version (optionally with a peer suffix).
	function childId(name, version) {
		if (major === 6 && object(packages[version])) { return version; }
		const base = version.split('(')[0].replace(/^\//, '');
		const at = base.indexOf('@');
		const colon = base.indexOf(':');
		return at !== -1 && (colon === -1 || at < colon) ? version : `${prefix}${name}@${version}`;
	}

	function packageEntry(id) {
		// v9 shares package metadata across peer contexts, but keeps their dependency snapshots separate.
		return major === 6 ? packages[id] : packages[id.split('(')[0]];
	}

	// Archive identities come from package metadata; directory identities come from their manifests.
	function identity(id) {
		const entry = packageEntry(id);
		const directory = entry?.resolution?.directory;
		if (typeof directory === 'string' || entry?.resolution?.type === 'directory') {
			if (typeof directory !== 'string') { unsupported(file, id, 'missing local package directory'); }
			const manifestFile = path.resolve(root, directory, 'package.json');
			if (!fs.existsSync(manifestFile)) { unsupported(file, id, 'missing local package manifest'); }
			const data = readJson(manifestFile);
			if (typeof data.name !== 'string' || !data.name || typeof data.version !== 'string' || !data.version) {
				unsupported(file, id, 'missing local package identity');
			}
			return { name: data.name, version: data.version };
		}
		const bare = id.startsWith('/') ? id.slice(1) : id;
		const parsed = bare.includes('@', 1) ? descriptor(bare.split('(')[0]) : {};
		const name = entry?.name ?? parsed.name;
		const version = entry?.version ?? parsed.range;
		if (typeof name !== 'string' || !name) { unsupported(file, id, 'missing locked package name'); }
		if (!semver.valid(version)) { unsupported(file, id, 'missing or invalid locked package version'); }
		return { name, version };
	}

	// Resolves a dependency edge to a node id, following workspace `link:` edges
	// to importers. Returns undefined when an optional dependency is absent.
	// `range` is the importer's recorded specifier (already validated to equal the
	// effective, override-applied manifest declaration); it is undefined for
	// transitive snapshot edges, which carry no declared range in the lockfile.
	function resolve(ownerLocation, name, version, source, optional, range) {
		if (version.startsWith('link:')) {
			const location = path.relative(root, path.resolve(root, ownerLocation, version.slice(5))).split(path.sep).join('/') || '.';
			if (locals.has(location) || object(importers[location])) { return `importer:${location}`; }
			unsupported(source, name, 'link protocol does not provide package dependency metadata; use a package-aware local protocol');
		}
		const id = childId(name, version);
		if (!object(snapshots[id])) {
			if (optional) { return undefined; }
			// A required edge points to a missing snapshot, so the locked graph is incomplete.
			stale(source, name, 'has no locked resolution');
		}
		// Even if declarations match, the resolved package's real version must still satisfy the range.
		if (range != null) { validateRange(source, name, range, identity(id)); }
		return id;
	}

	// Production edges exclude development dependencies; optional edges are
	// skipped when their resolution is absent.
	function edges(groups, source) {
		const out = [];
		for (const [group, optional] of groups) {
			if (group == null) { continue; }
			if (!object(group)) { unsupported(source, 'dependencies', 'expected a dependency mapping'); }
			for (const [name, entry] of Object.entries(group)) {
				const version = typeof entry === 'string' ? entry : entry?.version;
				if (typeof version !== 'string' || !version) { unsupported(source, name, 'missing resolved version'); }
				out.push([name, version, optional, typeof entry === 'string' ? undefined : entry?.specifier]);
			}
		}
		return out;
	}

	// An explicit stack avoids call-stack overflow on deep dependency chains.
	function visit(rootId) {
		const stack = [rootId];
		while (stack.length > 0) {
			const id = stack.pop();
			if (graph.nodes.has(id)) { continue; }
			const children = [];
			if (id.startsWith('importer:')) {
				const location = id.slice('importer:'.length);
				let local = locals.get(location);
				if (!local) {
					const manifestFile = path.resolve(root, location, 'package.json');
					const data = readJson(manifestFile);
					validatePnpmImporter(manifestFile, data, importers[location], file, override);
					local = { data, file: manifestFile };
					locals.set(location, local);
				}
				const source = local.file;
				const node = { name: local.data.name ?? location, version: local.data.version ?? 'v0.0.0', dependencies: new Map(), hashes: undefined };
				graph.nodes.set(id, node);
				const importer = importers[location];
				for (const [name, version, optional, specifier] of edges([[importer.dependencies, false], [importer.optionalDependencies, true]], source)) {
					const childNodeId = resolve(location, name, version, source, optional, specifier);
					if (childNodeId == null) { continue; }
					node.dependencies.set(name, childNodeId);
					children.push(childNodeId);
				}
			} else {
				const { name, version } = identity(id);
				const node = { name, version, dependencies: new Map(), hashes: hashes({ integrity: packageEntry(id)?.resolution?.integrity }) };
				graph.nodes.set(id, node);
				const snapshot = snapshots[id];
				for (const [depName, depVersion, optional] of edges([[snapshot?.dependencies, false], [snapshot?.optionalDependencies, true]], file)) {
					const childNodeId = resolve('.', depName, depVersion, file, optional);
					if (childNodeId == null) { continue; }
					node.dependencies.set(depName, childNodeId);
					children.push(childNodeId);
				}
			}
			// Push in reverse to visit dependencies in their original declaration order.
			for (let i = children.length - 1; i >= 0; i--) { stack.push(children[i]); }
		}
	}

	visit(graph.rootId);
	return graph;
}

/**
 * Reads a `bun.lock` document. Bun's text lockfile is JSONC (comments and
 * trailing commas allowed), so it is parsed leniently; genuine syntax errors
 * still surface as a read failure. Returns the parsed lockfile mapping.
 * @param {string} file - Absolute path to bun.lock
 * @returns {Object} The parsed lockfile mapping
 */
export function readBunLock(file) {
	let lock;
	try {
		const errors = [];
		lock = parseJsonc(fs.readFileSync(file, 'utf8'), errors, { allowTrailingComma: true });
		if (errors.length > 0) { throw new Error('invalid JSONC syntax'); }
		if (!object(lock)) { throw new Error('expected a lockfile mapping'); }
	} catch (cause) {
		throw new Error(`Cannot read ${file}: ${cause.message}`, { cause });
	}
	return lock;
}

/**
 * Parses a single `bun.lock` `packages` tuple. Bun uses several shapes:
 * npm `["name@version", registry, info, integrity]`, hosted/git
 * `["name@url", info, resolvedName, integrity]` (the info object shifts to
 * index 1), and a workspace pointer `["name@workspace:path"]` with no info.
 * The info object is located positionally and the integrity is the trailing
 * string, so all shapes parse through one code path.
 * @param {Array} tuple - A `bun.lock` packages entry
 * @returns {{id: string, name: string, range: string, version: string,
 *   info: Object, integrity: (string|undefined), workspace: boolean}}
 */
export function parseBunEntry(tuple) {
	const id = tuple[0];
	const { name, range } = descriptor(id);
	const info = tuple.slice(1).find(object) ?? {};
	const last = tuple.length > 1 ? tuple[tuple.length - 1] : undefined;
	const integrity = typeof last === 'string' ? last : undefined;
	const workspace = range.startsWith('workspace:');
	// For registry packages the range is the resolved version; for hosted/git
	// packages it is the URL/ref, which is preserved as the reported version.
	return { id, name, range, version: workspace ? undefined : range, info, integrity, workspace };
}

/**
 * Reads Bun's resolved graph from a text `bun.lock` without invoking Bun.
 * Supports lockfileVersion 0, 1 and 2. Package identities come from each
 * tuple's resolved `name@version` (so npm aliases report their real target),
 * nested resolutions are keyed by their `parent/child` install path (so
 * conflicting versions stay distinct), workspace members resolve to their
 * on-disk manifest identity, and optional branches are preserved while missing
 * required resolutions are rejected.
 * @param {string} root - Workspace root (directory holding bun.lock)
 * @param {string} manifestPath - Path to the analyzed package.json
 * @param {Object} manifest - Parsed package.json content
 * @param {Object} lock - Parsed lockfile (see {@link readBunLock})
 * @returns {LockGraph} The resolved dependency graph
 */
export function readBunGraph(root, manifestPath, manifest, lock) {
	const file = path.join(root, 'bun.lock');
	if (![0, 1, 2].includes(lock.lockfileVersion)) {
		throw new Error(
			`Unsupported bun lockfile version ${lock.lockfileVersion} in ${file}. `
			+ `Regenerate a version 0, 1, or 2 bun.lock before scanning.`
		);
	}
	if (!object(lock.workspaces)) { unsupported(file, 'workspaces', 'missing workspaces table'); }
	const workspaces = lock.workspaces;
	const packages = object(lock.packages) ? lock.packages : {};

	const manifests = projectManifests(root, manifestPath, manifest);
	const rootFile = path.join(root, 'package.json');
	const rootData = manifests.get(rootFile);
	const overrideField = Object.hasOwn(rootData, 'overrides') ? 'overrides' : 'resolutions';
	const overrideEntries = Object.entries(dependencyMap(rootData, overrideField, rootFile));
	const overrides = Object.fromEntries(overrideEntries.map(([name, spec]) => {
		if (overrideField === 'resolutions') { name = name.replace(/^\*\*\//, ''); }
		if (spec.startsWith('$')) {
			const dependencies = {
				...dependencyMap(rootData, 'peerDependencies', rootFile),
				...manifestDependencies(rootData, rootFile, true),
			};
			spec = dependencies[spec.slice(1)];
			if (typeof spec !== 'string' || !spec) {
				unsupported(rootFile, name, 'override reference has no declared dependency');
			}
		}
		return [name, spec];
	}));
	validateSnapshot(rootFile, { overrides }, lock, ['overrides']);
	const locals = new Map();
	for (const [manifestFile, data] of manifests) {
		const location = path.relative(root, path.dirname(manifestFile))
			.split(path.sep).join('/') || '.';
		const entry = workspaces[location === '.' ? '' : location];
		if (!object(entry)) { stale(manifestFile, data.name, 'is missing from the lockfile'); }
		if (entry.name != null && data.name !== entry.name) {
			stale(manifestFile, data.name, 'has a different locked identity');
		}
		const snapshot = {
			dependencies: { ...dependencyMap(data, 'dependencies', manifestFile) },
			devDependencies: { ...dependencyMap(data, 'devDependencies', manifestFile) },
			optionalDependencies: dependencyMap(data, 'optionalDependencies', manifestFile),
			peerDependencies: data.peerDependencies,
		};
		// Bun replaces the production declaration first, otherwise the development declaration.
		for (const name of Object.keys(snapshot.optionalDependencies)) {
			if (Object.hasOwn(snapshot.dependencies, name)) { delete snapshot.dependencies[name]; }
			else { delete snapshot.devDependencies[name]; }
		}
		validateSnapshot(manifestFile, snapshot, entry, [
			'dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies',
		]);
		locals.set(location, {
			data, file: manifestFile, packageKey: location === '.' ? '' : data.name,
			devDependencies: snapshot.devDependencies,
		});
	}
	const rootLocation = path.relative(root, path.dirname(path.resolve(manifestPath)))
		.split(path.sep).join('/') || '.';
	if (!locals.has(rootLocation)) {
		unsupported(file, manifest.name, 'manifest is not in the workspace');
	}

	// Resolves a dependency to its `packages` key using Bun's node_modules
	// hoisting: a `parent/child` nested entry wins over a hoisted top-level one,
	// walking up the owner's install path before falling back to the root.
	function resolveKey(ownerPath, name) {
		const parts = ownerPath ? ownerPath.split('/') : [];
		while (true) {
			const candidate = [...parts, name].join('/');
			if (packages[candidate] !== undefined) { return candidate; }
			if (parts.length === 0) { return undefined; }
			parts.pop();
			// A scope and its package name occupy one resolution level.
			if (parts.at(-1)?.startsWith('@')) { parts.pop(); }
		}
	}

	const graph = { rootId: `ws:${rootLocation}`, nodes: new Map() };

	// Resolves one dependency edge to a node id. Returns undefined for an absent
	// optional edge; throws for an absent required edge. Workspace pointers
	// redirect to the member's importer node.
	function childId(ownerPath, name, spec, source, optional) {
		const key = resolveKey(ownerPath, name);
		if (key === undefined) {
			if (optional) { return undefined; }
			stale(source, name, 'has no locked resolution');
		}
		const entry = packages[key];
		if (!Array.isArray(entry) || typeof entry[0] !== 'string') {
			unsupported(file, key, 'malformed package entry');
		}
		const parsed = parseBunEntry(entry);
		if (parsed.workspace) {
			const location = parsed.range.slice('workspace:'.length) || '.';
			const local = locals.get(location);
			if (!local) { unsupported(file, key, 'workspace package missing from the lockfile'); }
			if (spec != null && !['workspace:*', 'workspace:^', 'workspace:~'].includes(spec)) {
				validateRange(source, name, spec, {
					name: local.data.name, version: local.data.version ?? 'v0.0.0',
				});
			}
			return `ws:${location}`;
		}
		const aliased = spec?.startsWith('npm:') && !semver.validRange(spec.slice(4));
		const effective = !aliased && Object.hasOwn(overrides, name) ? overrides[name] : spec;
		if (effective != null) {
			validateRange(source, name, effective, { name: parsed.name, version: parsed.version });
		}
		return key;
	}

	// An explicit stack avoids call-stack overflow on deep dependency chains.
	function visit(startId) {
		const stack = [startId];
		while (stack.length > 0) {
			const id = stack.pop();
			if (graph.nodes.has(id)) { continue; }
			const children = [];
			if (id.startsWith('ws:')) {
				const local = locals.get(id.slice(3));
				const node = {
					name: local.data.name ?? path.basename(path.dirname(local.file)),
					version: local.data.version ?? 'v0.0.0',
					dependencies: new Map(),
					hashes: undefined,
				};
				graph.nodes.set(id, node);
				const optionalDeps = local.data.optionalDependencies ?? {};
				for (const [name, spec] of Object.entries(
					manifestDependencies(local.data, local.file)
				)) {
					const devSpec = local.devDependencies[name];
					// Bun may lock either range when it retains both declarations for
					// the same name.
					const bothRanges = typeof devSpec === 'string'
						&& semver.validRange(spec) && semver.validRange(devSpec);
					const effective = bothRanges ? `${spec} || ${devSpec}` : spec;
					const cid = childId(local.packageKey, name, effective, local.file,
						Object.hasOwn(optionalDeps, name));
					if (cid == null) { continue; }
					node.dependencies.set(name, cid);
					children.push(cid);
				}
			} else {
				const parsed = parseBunEntry(packages[id]);
				const validId = typeof parsed.name === 'string' && parsed.name
					&& typeof parsed.version === 'string' && parsed.version;
				if (!validId) {
					unsupported(file, id, 'missing package name or version');
				}
				const node = {
					name: parsed.name, version: parsed.version,
					dependencies: new Map(), hashes: hashes({ integrity: parsed.integrity }),
				};
				graph.nodes.set(id, node);
				for (const field of ['dependencies', 'optionalDependencies']) {
					if (Object.hasOwn(parsed.info, field) && !object(parsed.info[field])) {
						throw new Error(
							`Invalid ${field} in ${file} for ${id}: `
							+ `expected a dependency mapping.`
						);
					}
				}
				const required = dependencyMap(parsed.info, 'dependencies', `${file} for ${id}`);
				const optionalDeps =
					dependencyMap(parsed.info, 'optionalDependencies', `${file} for ${id}`);
				// ponytail: transitive peerDependencies are omitted (as the prior
				// reader did); direct peers are supplemented by the SBOM builder. Add
				// peer-edge resolution here if a fixture ever needs transitive peers.
				for (const [name, spec] of Object.entries(required)) {
					const cid = childId(id, name, spec, file, false);
					if (cid == null) { continue; }
					node.dependencies.set(name, cid);
					children.push(cid);
				}
				for (const [name, spec] of Object.entries(optionalDeps)) {
					if (node.dependencies.has(name)) { continue; }
					const cid = childId(id, name, spec, file, true);
					if (cid == null) { continue; }
					node.dependencies.set(name, cid);
					children.push(cid);
				}
			}
			// Push in reverse to visit dependencies in their original declaration order.
			for (let i = children.length - 1; i >= 0; i--) { stack.push(children[i]); }
		}
	}

	visit(graph.rootId);
	return graph;
}
