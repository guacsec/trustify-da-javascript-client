import fs from 'node:fs'
import { EOL } from 'os'

import { PackageURL } from 'packageurl-js'

import Sbom from '../sbom.js'
import {
	environmentVariableIsPopulated,
	getCustom,
	getCustomPath,
	invokeCommand
} from "../tools.js";


import Python_controller from './python_controller.js'

export default { isSupported, validateLockFile, provideComponent, provideStack }

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
 * @param {string} manifestDir - the directory where the manifest lies
 */
function validateLockFile() { return true; }

/**
 * Provide content and content type for python-pip stack analysis.
 * @param {string} manifest - the manifest path or name
 * @param {{}} [opts={}] - optional various options to pass along the application
 * @returns {Provided}
 */
function provideStack(manifest, opts = {}) {
	return {
		ecosystem,
		content: createSbomStackAnalysis(manifest, opts),
		contentType: 'application/vnd.cyclonedx+json'
	}
}

/**
 * Provide content and content type for python-pip component analysis.
 * @param {string} manifest - path to requirements.txt for component report
 * @param {{}} [opts={}] - optional various options to pass along the application
 * @returns {Provided}
 */
function provideComponent(manifest, opts = {}) {
	return {
		ecosystem,
		content: getSbomForComponentAnalysis(manifest, opts),
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
		directDeps.forEach( (dependency) =>{ addAllDependencies(toPurl(dep["name"],dep["version"]), dependency, sbom)})
	}
}

/**
 *
 * @param nameVersion
 * @return {string}
 */
function splitToNameVersion(nameVersion) {
	let result = []
	if(nameVersion.includes("==")) {
		return nameVersion.split("==")
	}
	const regex = /[^\w\s-_]/g;
	let endIndex = nameVersion.search(regex);
	if(endIndex === -1) {
		return [nameVersion.trim()]
	}
	result.push(nameVersion.substring(0, endIndex).trim())
	return result;
}

/**
 *
 * @param {string} requirementTxtContent
 * @return {PackageURL []}
 */
function getIgnoredDependencies(requirementTxtContent) {
	let requirementsLines = requirementTxtContent.split(EOL)
	return requirementsLines
		.filter(line => line.includes("#exhortignore") || line.includes("# exhortignore"))
		.map((line) => line.substring(0,line.indexOf("#")).trim())
		.map((name) => {
			let nameVersion = splitToNameVersion(name);
			if(nameVersion.length === 2) {
				return toPurl(nameVersion[0],nameVersion[1])
			}
			return toPurl(nameVersion[0], undefined);
		})
}

/**
 *
 * @param {string} requirementTxtContent content of requirments.txt in string
 * @param {Sbom} sbom object to filter out from it exhortignore dependencies.
 * @param {{Object}} opts - various options and settings for the application
 * @private
 */
function handleIgnoredDependencies(requirementTxtContent, sbom, opts ={}) {
	let ignoredDeps = getIgnoredDependencies(requirementTxtContent)
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
function getPythonPipBinaries(binaries,opts) {
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
 * @returns {string} the sbom json string content
 * @private
 */
function createSbomStackAnalysis(manifest, opts = {}) {
	let binaries = {}
	let createVirtualPythonEnv = handlePythonEnvironment(binaries, opts);

	let pythonController = new Python_controller(createVirtualPythonEnv === "false", binaries.pip, binaries.python, manifest, opts)
	let dependencies = pythonController.getDependencies(true);
	let sbom = new Sbom();
	const rootPurl = toPurl(DEFAULT_PIP_ROOT_COMPONENT_NAME, DEFAULT_PIP_ROOT_COMPONENT_VERSION);
	sbom.addRoot(rootPurl);
	dependencies.forEach(dep => {
		addAllDependencies(rootPurl, dep, sbom)
	})
	let requirementTxtContent = fs.readFileSync(manifest).toString();
	handleIgnoredDependencies(requirementTxtContent, sbom, opts)
	// In python there is no root component, then we must remove the dummy root we added, so the sbom json will be accepted by exhort backend
	// sbom.removeRootComponent()
	return sbom.getAsJsonString(opts)
}

/**
 * Create a sbom json string out of a manifest content for component analysis
 * @param {string} manifest - path to requirements.txt
 * @param {{}} [opts={}] - optional various options to pass along the application
 * @returns {string} the sbom json string content
 * @private
 */
function getSbomForComponentAnalysis(manifest, opts = {}) {
	let binaries = {}
	let createVirtualPythonEnv = handlePythonEnvironment(binaries, opts);
	let pythonController = new Python_controller(createVirtualPythonEnv === "false", binaries.pip, binaries.python, manifest, opts)
	let dependencies = pythonController.getDependencies(false);
	let sbom = new Sbom();
	const rootPurl = toPurl(DEFAULT_PIP_ROOT_COMPONENT_NAME, DEFAULT_PIP_ROOT_COMPONENT_VERSION);
	sbom.addRoot(rootPurl);
	dependencies.forEach(dep => {
		sbom.addDependency(rootPurl, toPurl(dep.name, dep.version))
	})
	let requirementTxtContent = fs.readFileSync(manifest).toString();
	handleIgnoredDependencies(requirementTxtContent, sbom, opts)
	// In python there is no root component, then we must remove the dummy root we added, so the sbom json will be accepted by exhort backend
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
