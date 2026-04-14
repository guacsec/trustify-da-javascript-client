import fs from "fs";

import { toPurl } from "../tools.js";

const DEFAULT_VERSION = 'v0.0.0';
export default class Manifest {

	constructor(manifestPath) {
		if (!manifestPath) {
			throw new Error("Missing required manifest path");
		}
		this.manifestPath = manifestPath;
		const content = this.loadManifest();
		this.dependencies = this.loadDependencies(content);
		this.peerDependencies = content.peerDependencies || {};
		this.optionalDependencies = content.optionalDependencies || {};
		this.name = content.name;
		this.version = content.version || DEFAULT_VERSION;
		this.ignored = this.loadIgnored(content);
	}

	loadManifest() {
		try {
			let manifest = JSON.parse(fs.readFileSync(this.manifestPath, 'utf-8'));
			return manifest;} catch (err) {
			if(err.code === 'ENOENT') {
				throw new Error("Missing manifest file: " + this.manifestPath, {cause: err});
			}
			throw new Error("Unable to parse manifest: " + this.manifestPath, {cause: err});
		}
	}

	loadDependencies(content) {
		let deps = [];
		const depSources = [
			content.dependencies,
			content.peerDependencies,
			content.optionalDependencies,
		];
		for (const source of depSources) {
			if (source) {
				for (let dep in source) {
					if (!deps.includes(dep)) {
						deps.push(dep);
					}
				}
			}
		}
		// bundledDependencies is an array of package names (subset of dependencies)
		if (Array.isArray(content.bundledDependencies)) {
			for (const dep of content.bundledDependencies) {
				if (!deps.includes(dep)) {
					deps.push(dep);
				}
			}
		}
		return deps;
	}

	loadIgnored(content) {
		let deps = [];
		if(!content.exhortignore) {
			return deps;
		}
		for(let i = 0; i < content.exhortignore.length; i++) {
			deps.push(toPurl("npm", content.exhortignore[i]));
		}
		return deps;
	}
}
