import fs from 'node:fs';
import path from 'node:path';

import { parseResolution, parseSyml } from '@yarnpkg/parsers';
import glob from 'fast-glob';
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
