import path from 'node:path'

import golangGomodulesProvider from './providers/golang_gomodules.js'
import Java_gradle_groovy from "./providers/java_gradle_groovy.js";
import Java_gradle_kotlin from "./providers/java_gradle_kotlin.js";
import Java_maven from "./providers/java_maven.js";
import Javascript_npm from './providers/javascript_npm.js';
import Javascript_pnpm from './providers/javascript_pnpm.js';
import Javascript_yarn from './providers/javascript_yarn.js';
import pythonPipProvider from './providers/python_pip.js'
import rustCargoProvider from './providers/rust_cargo.js'

/** @typedef {{ecosystem: string, contentType: string, content: string}} Provided */
/** @typedef {{isSupported: function(string): boolean, validateLockFile: function(string): void, provideComponent: function(string, {}): Provided | Promise<Provided>, provideStack: function(string, {}): Provided | Promise<Provided>, readLicenseFromManifest: function(string): string | null}} Provider */

/**
 * MUST include all providers here.
 * @type {[Provider]}
 */
export const availableProviders = [
	new Java_maven(),
	new Java_gradle_groovy(),
	new Java_gradle_kotlin(),
	new Javascript_npm(),
	new Javascript_pnpm(),
	new Javascript_yarn(),
	golangGomodulesProvider,
	pythonPipProvider,
	rustCargoProvider]

/**
 * Match a provider by manifest type only (no lock file check). Used for license reading.
 * @param {string} manifestPath - path or name of the manifest
 * @param {[Provider]} providers - list of providers to iterate over
 * @returns {Provider}
 * @throws {Error} when the manifest is not supported and no provider was matched
 */
export function matchForLicense(manifestPath, providers) {
	const base = path.parse(manifestPath).base
	const provider = providers.find(prov => prov.isSupported(base))
	if (!provider) {
		throw new Error(`${base} is not supported`)
	}
	return provider
}

/**
 * Match a provider from a list or providers based on file type.
 * Each provider MUST export 'isSupported' taking a file name-type and returning true if supported.
 * Each provider MUST export 'provideComponent' taking manifest data returning a {@link Provided}.
 * Each provider MUST export 'provideStack' taking manifest path returning a {@link Provided}.
 * @param {string} manifest - the name-type or path of the manifest
 * @param {[Provider]} providers - list of providers to iterate over
 * @returns {Provider}
 * @throws {Error} when the manifest is not supported and no provider was matched
 */
export function match(manifest, providers) {
	const manifestPath = path.parse(manifest)
	const supported = providers.filter(prov => prov.isSupported(manifestPath.base))
	if (supported.length === 0) {
		throw new Error(`${manifestPath.base} is not supported`)
	}
	const provider = supported.find(prov => prov.validateLockFile(manifestPath.dir))
	if(!provider) {
		throw new Error(`${manifestPath.base} requires a lock file. Use your preferred package manager to generate the lock file.`);
	}
	return provider
}
