import fs from 'node:fs'

import { PackageURL } from 'packageurl-js'

import { readLicenseFile } from '../license/license_utils.js'
import Sbom from '../sbom.js'
import {
	environmentVariableIsPopulated,
	getCustom,
	getCustomPath,
	invokeCommand
} from "../tools.js";

import Python_controller from './python_controller.js'
import { getParser, getIgnoreQuery, getPinnedVersionQuery } from './requirements_parser.js'

export default { isSupported, validateLockFile, provideComponent, provideStack, readLicenseFromManifest }

/** @typedef {{name: string, version: string, dependencies: DependencyEntry[]}} DependencyEntry */

/**
 * @type {string} ecosystem for python-pip is 'pip'
 * @private
 */
const ecosystem = 'pip'

/**
 * @param {string} manifestName - the subject manifest name-type
 * @returns {boolean} - return true if `requirements.txt` is the manifest name-type
 */
function isSupported(manifestName) {
	return 'requirements.txt' === manifestName
}

/**
 * Python requirements.txt has no standard license field
 * @param {string} manifestPath - path to requirements.txt
 * @returns {string|null}
 */
// eslint-disable-next-line no-unused-vars
function readLicenseFromManifest(manifestPath) { return readLicenseFile(manifestPath); }

/**
 * @param {string} manifestDir - the directory where the manifest lies
 */
function validateLockFile() { return true; }

/**
 * Provide content and content type for python-pip stack analysis.
 * @param {string} manifest - the manifest path or name
 * @param {{}} [opts={}] - optional various options to pass along the application
 * @returns {Promise<Provided>}
 */
async function provideStack(manifest, opts = {}) {
	return {
		ecosystem,
		content: await createSbomStackAnalysis(manifest, opts),
		contentType: 'application/vnd.cyclonedx+json'
	}
}

/**
 * Provide content and content type for python-pip component analysis.
 * @param {string} manifest - path to requirements.txt for component report
 * @param {{}} [opts={}] - optional various options to pass along the application
 * @returns {Promise<Provided>}
 */
async function provideComponent(manifest, opts = {}) {
	return {
		ecosystem,
		content: await getSbomForComponentAnalysis(manifest, opts),
		contentType: 'application/vnd.cyclonedx+json'
	}
}

/** @typedef {{name: string, , version: string, dependencies: DependencyEntry[]}} DependencyEntry */

/**
 *
 * @param {PackageURL}source
 * @param {DependencyEntry} dep
 * @param {Sbom} sbom
 * @private
 */
function addAllDependencies(source, dep, sbom) {
	let targetPurl = toPurl(dep["name"], dep["version"])
	sbom.addDependency(source, targetPurl)
	let directDeps = dep["dependencies"]
	if (directDeps !== undefined && directDeps.length > 0) {
		directDeps.forEach((dependency) => { addAllDependencies(toPurl(dep["name"],dep["version"]), dependency, sbom) })
	}
}

/**
 *
 * @param {string} manifest - path to requirements.txt
 * @return {PackageURL []}
 */
async function getIgnoredDependencies(manifest) {
	const [parser, ignoreQuery, pinnedVersionQuery] = await Promise.all([
		getParser(), getIgnoreQuery(), getPinnedVersionQuery()
	]);
	const content = fs.readFileSync(manifest).toString();
	const tree = parser.parse(content);
	return ignoreQuery.matches(tree.rootNode).map(match => {
		const reqNode = match.captures.find(c => c.name === 'req').node;
		const name = match.captures.find(c => c.name === 'name').node.text;
		const versionMatches = pinnedVersionQuery.matches(reqNode);
		const version = versionMatches.length > 0
			? versionMatches[0].captures.find(c => c.name === 'version').node.text
			: undefined;
		return toPurl(name, version);
	})
}

/**
 *
 * @param {string} manifest - path to requirements.txt
 * @param {Sbom} sbom object to filter out from it exhortignore dependencies.
 * @param {{Object}} opts - various options and settings for the application
 * @private
 */
async function handleIgnoredDependencies(manifest, sbom, opts = {}) {
	let ignoredDeps = await getIgnoredDependencies(manifest)
	let matchManifestVersions = getCustom("MATCH_MANIFEST_VERSIONS", "true", opts);
	if(matchManifestVersions === "true") {
		const ignoredDepsVersion = ignoredDeps.filter(dep => dep.version !== undefined);
		sbom.filterIgnoredDepsIncludingVersion(ignoredDepsVersion.map(dep => dep.toString()))
	} else {
		// in case of version mismatch, need to parse the name of package from the purl, and remove the package name from sbom according to name only
		// without version
		sbom.filterIgnoredDeps(ignoredDeps)
	}
}

/** get python and pip binaries, python3/pip3 get precedence if exists on the system path
 * @param {object}binaries
 * @param {{}} [opts={}]
 */
function getPythonPipBinaries(binaries, opts) {
	let python = getCustomPath("python3", opts)
	let pip = getCustomPath("pip3", opts)
	try {
		invokeCommand(python, ['--version'])
		invokeCommand(pip, ['--version'])
	} catch (error) {
		python = getCustomPath("python", opts)
		pip = getCustomPath("pip", opts)
		try {
			invokeCommand(python, ['--version'])
			invokeCommand(pip, ['--version'])
		} catch (error) {
			throw new Error(`Failed checking for python/pip binaries from supplied environment variables`, {cause: error})
		}
	}
	binaries.pip = pip
	binaries.python = python
}

/**
 *
 * @param binaries
 * @param opts
 * @return {string}
 * @private
 */
function handlePythonEnvironment(binaries, opts) {
	let createVirtualPythonEnv
	if (!environmentVariableIsPopulated("TRUSTIFY_DA_PIP_SHOW") && !environmentVariableIsPopulated("TRUSTIFY_DA_PIP_FREEZE")) {
		getPythonPipBinaries(binaries, opts)
		createVirtualPythonEnv = getCustom("TRUSTIFY_DA_PYTHON_VIRTUAL_ENV", "false", opts);
	}
	// bypass invoking python and pip, as we get all information needed to build the dependency tree from these Environment variables.
	else {
		binaries.pip = "pip"
		binaries.python = "python"
		createVirtualPythonEnv = "false"
	}
	return createVirtualPythonEnv
}

const DEFAULT_PIP_ROOT_COMPONENT_NAME = "default-pip-root";

const DEFAULT_PIP_ROOT_COMPONENT_VERSION = "0.0.0";

/**
 * Create sbom json string out of a manifest path for stack analysis.
 * @param {string} manifest - path for requirements.txt
 * @param {{}} [opts={}] - optional various options to pass along the application
 * @returns {Promise<string>} the sbom json string content
 * @private
 */
async function createSbomStackAnalysis(manifest, opts = {}) {
	let binaries = {}
	let createVirtualPythonEnv = handlePythonEnvironment(binaries, opts);

	let pythonController = new Python_controller(createVirtualPythonEnv === "false", binaries.pip, binaries.python, manifest, opts)
	let dependencies = await pythonController.getDependencies(true);
	let sbom = new Sbom();
	const rootPurl = toPurl(DEFAULT_PIP_ROOT_COMPONENT_NAME, DEFAULT_PIP_ROOT_COMPONENT_VERSION);
	const license = readLicenseFromManifest(manifest);
	sbom.addRoot(rootPurl, license);
	dependencies.forEach(dep => {
		addAllDependencies(rootPurl, dep, sbom)
	})
	await handleIgnoredDependencies(manifest, sbom, opts)
	// In python there is no root component, then we must remove the dummy root we added, so the sbom json will be accepted by the DA backend
	// sbom.removeRootComponent()
	return sbom.getAsJsonString(opts)
}

/**
 * Create a sbom json string out of a manifest content for component analysis
 * @param {string} manifest - path to requirements.txt
 * @param {{}} [opts={}] - optional various options to pass along the application
 * @returns {Promise<string>} the sbom json string content
 * @private
 */
async function getSbomForComponentAnalysis(manifest, opts = {}) {
	let binaries = {}
	let createVirtualPythonEnv = handlePythonEnvironment(binaries, opts);
	let pythonController = new Python_controller(createVirtualPythonEnv === "false", binaries.pip, binaries.python, manifest, opts)
	let dependencies = await pythonController.getDependencies(false);
	let sbom = new Sbom();
	const rootPurl = toPurl(DEFAULT_PIP_ROOT_COMPONENT_NAME, DEFAULT_PIP_ROOT_COMPONENT_VERSION);
	const license = readLicenseFromManifest(manifest);
	sbom.addRoot(rootPurl, license);
	dependencies.forEach(dep => {
		sbom.addDependency(rootPurl, toPurl(dep.name, dep.version))
	})
	await handleIgnoredDependencies(manifest, sbom, opts)
	// In python there is no root component, then we must remove the dummy root we added, so the sbom json will be accepted by the DA backend
	// sbom.removeRootComponent()
	return sbom.getAsJsonString(opts)
}

/**
 * Returns a PackageUrl For pip dependencies
 * @param name
 * @param version
 * @return {PackageURL}
 */
function toPurl(name,version) {
	return new PackageURL('pypi', undefined, name, version, undefined, undefined);
}
