import fs from 'node:fs'
import path from 'node:path'

import { PackageURL } from 'packageurl-js'

import { readLicenseFile } from '../license/license_utils.js'
import Sbom from '../sbom.js'
import { getCustom, getCustomPath, invokeCommand } from "../tools.js";

import { getParser, getRequireQuery } from './gomod_parser.js'

export default { isSupported, validateLockFile, provideComponent, provideStack, readLicenseFromManifest }

/** @typedef {import('../provider').Provider} */

/** @typedef {import('../provider').Provided} Provided */

/** @typedef {{name: string, version: string}} Package */

/** @typedef {{groupId: string, artifactId: string, version: string, scope: string, ignore: boolean}} Dependency */

/**
 * @type {string} ecosystem for npm-npm is 'maven'
 * @private
*/
const ecosystem = 'golang'
const defaultMainModuleVersion = "v0.0.0";

/**
 * @param {string} manifestName the subject manifest name-type
 * @returns {boolean} return true if `pom.xml` is the manifest name-type
*/
function isSupported(manifestName) {
	return 'go.mod' === manifestName
}

/**
 * Go modules have no standard license field in go.mod
 * @param {string} manifestPath path to go.mod
 * @returns {string|null}
*/
// eslint-disable-next-line no-unused-vars
function readLicenseFromManifest(manifestPath) { return readLicenseFile(manifestPath); }

/**
 * @param {string} manifestDir the directory where the manifest lies
 */
function validateLockFile() { return true; }

/**
 * Provide content and content type for maven-maven stack analysis.
 * @param {string} manifest the manifest path or name
 * @param {{}} [opts={}] optional various options to pass along the application
 * @returns {Promise<Provided>}
 */
async function provideStack(manifest, opts = {}) {
	return {
		ecosystem,
		content: await getSBOM(manifest, opts, true),
		contentType: 'application/vnd.cyclonedx+json'
	}
}

/**
 * Provide content and content type for maven-maven component analysis.
 * @param {string} manifest path to go.mod for component report
 * @param {{}} [opts={}] optional various options to pass along the application
 * @returns {Promise<Provided>}
 */
async function provideComponent(manifest, opts = {}) {
	return {
		ecosystem,
		content: await getSBOM(manifest, opts, false),
		contentType: 'application/vnd.cyclonedx+json'
	}
}

/**
 *
 * @param {string} edge containing an edge of direct graph of source dependency (parent) and target dependency (child)
 * @return {string} the parent (source) dependency
 */
function getParentVertexFromEdge(edge) {
	return edge.split(" ")[0];
}
/**
 *
 * @param {string} edge containing an edge of direct graph of source dependency (parent) and target dependency (child)
 * @return {string} the child (target) dependency
 */
function getChildVertexFromEdge(edge) {
	return edge.split(" ")[1];
}

/**
 * Check whether a require_spec has a valid exhortignore marker.
 * For direct dependencies: `//exhortignore` or `// exhortignore`
 * For indirect dependencies: `// indirect; exhortignore` (semicolon-separated)
 * @param {import('web-tree-sitter').SyntaxNode} specNode
 * @return {boolean}
 */
function hasExhortIgnore(specNode) {
	// Ideally this would be the following tree-sitter query instead, but for some
	// reason it throws an error here but not in the playground.
	// (require_spec) ((module_path) @path (version) (comment) @comment (#match? @comment "^//.*exhortignore"))
	// QueryError: Bad pattern structure at offset 53: '(comment) @comment (#match? @comment "^//.*exhortignore")) @spec'...
	let comments = specNode.children.filter(c => c.type === 'comment')
	for (let comment of comments) {
		let text = comment.text
		if (/^\/\/\s*indirect;\s*exhortignore/.test(text)) {
			return true
		}
		if (/^\/\/\s*exhortignore/.test(text)) {
			return true
		}
	}
	return false
}

/**
 *
 * @param {string} manifestContent go.mod file contents
 * @param {import('web-tree-sitter').Parser} parser
 * @param {import('web-tree-sitter').Query} requireQuery
 * @return {PackageURL[]} list of ignored dependencies
 */
function getIgnoredDeps(manifestContent, parser, requireQuery) {
	let tree = parser.parse(manifestContent)
	return requireQuery.matches(tree.rootNode)
		.filter(match => {
			let specNode = match.captures.find(c => c.name === 'spec').node
			return hasExhortIgnore(specNode)
		})
		.map(match => {
			let name = match.captures.find(c => c.name === 'name').node.text
			let version = match.captures.find(c => c.name === 'version').node.text
			return toPurl(`${name} ${version}`, /[ ]{1,3}/)
		})
}

/**
 *
 * @param {PackageURL[]} allIgnoredDeps list of purls of all dependencies that should be ignored
 * @param {PackageURL} purl object to be checked if needed to be ignored
 * @return {boolean}
 */
function dependencyNotIgnored(allIgnoredDeps, purl) {
	return allIgnoredDeps.find(element => element.toString() === purl.toString()) === undefined;
}

function enforceRemovingIgnoredDepsInCaseOfAutomaticVersionUpdate(ignoredDeps, sbom) {
	// In case there is a dependency commented with exhortignore , but it is still in the list of direct dependencies of root, then
	// the reason for that is that go mod graph changed automatically the version of package/module to different version, and because of
	// mismatch between the version in go.mod manifest and go mod graph, it wasn't delete ==> in this case need to remove from sbom according to name only.
	ignoredDeps.forEach(packageUrl => {
		if (sbom.checkIfPackageInsideDependsOnList(sbom.getRoot(), packageUrl.name)) {
			sbom.filterIgnoredDeps(ignoredDeps.filter(purl => purl.name === packageUrl.name).map(purl => purl.name))
		}
	})
}

/**
 *
 * @param {string} manifestContent go.mod file contents
 * @param {import('web-tree-sitter').Parser} parser
 * @param {import('web-tree-sitter').Query} requireQuery
 * @return {string[]} all dependencies from go.mod file as "name version" strings
 */
function collectAllDepsFromManifest(manifestContent, parser, requireQuery) {
	let tree = parser.parse(manifestContent)
	return requireQuery.matches(tree.rootNode).map(match => {
		let name = match.captures.find(c => c.name === 'name').node.text
		let version = match.captures.find(c => c.name === 'version').node.text
		return `${name} ${version}`
	})
}

/**
 *
 * @param {string} rootElementName the rootElementName element of go mod graph, to compare only direct deps from go mod graph against go.mod manifest
 * @param {string[]} goModGraphOutputRows the goModGraphOutputRows from go mod graph' output
 * @param {string} manifestContent go.mod file contents
 * @private
 */
function performManifestVersionsCheck(rootElementName, goModGraphOutputRows, manifestContent, parser, requireQuery) {
	let comparisonLines = goModGraphOutputRows.filter((line)=> line.startsWith(rootElementName)).map((line)=> getChildVertexFromEdge(line))
	let manifestDeps = collectAllDepsFromManifest(manifestContent, parser, requireQuery)
	try {
		comparisonLines.forEach((dependency) => {
			let parts = dependency.split("@")
			let version = parts[1]
			let depName = parts[0]
			manifestDeps.forEach(dep => {
				let components = dep.trim().split(" ");
				let currentDepName = components[0]
				let currentVersion = components[1]
				if (currentDepName === depName) {
					if (currentVersion !== version) {
						throw new Error(`version mismatch for dependency "${depName}", manifest version=${currentVersion}, installed version=${version}, if you want to allow version mismatch for analysis between installed and requested packages, set environment variable/setting MATCH_MANIFEST_VERSIONS=false`)
					}
				}
			})
		})
	}
	catch(error) {
		console.error("Can't continue with analysis")
		throw error
	}
}

/**
 * Create SBOM json string for go Module.
 * @param {string} manifest - path for go.mod
 * @param {{}} [opts={}] - optional various options to pass along the application
 * @param {boolean} includeTransitive - whether the sbom should contain transitive dependencies of the main module or not.
 * @returns {Promise<string>} the SBOM json content
 * @private
 */
async function getSBOM(manifest, opts = {}, includeTransitive) {
	// get custom goBin path
	let goBin = getCustomPath('go', opts)
	// verify goBin is accessible
	try {
		invokeCommand(goBin, ['version'])
	} catch(error) {
		if (error.code === 'ENOENT') {
			throw new Error(`go binary is not accessible at "${goBin}"`)
		}
		throw new Error(`failed to check for go binary`, {cause: error})
	}
	let manifestDir = path.dirname(manifest)
	try {
		var goGraphOutput = invokeCommand(goBin, ['mod', 'graph'], {cwd: manifestDir}).toString().trim()
	} catch(error) {
		throw new Error('failed to invoke go binary for module graph', {cause: error})
	}

	try {
		var goModEditOutput = JSON.parse(invokeCommand(goBin, ["mod", "edit", "-json"], {cwd: manifestDir}).toString().trim())
	} catch(error) {
		throw new Error('failed to determine root module name', {cause: error})
	}

	let manifestContent = fs.readFileSync(manifest).toString()
	let [parser, requireQuery] = await Promise.all([getParser(), getRequireQuery()]);
	let ignoredDeps = getIgnoredDeps(manifestContent, parser, requireQuery);
	let allIgnoredDeps = ignoredDeps.map((dep) => dep.toString())
	let sbom = new Sbom();
	let rows = goGraphOutput.split(getLineSeparatorGolang()).filter(line => !line.includes(' go@'));
	let root = goModEditOutput['Module']['Path']

	// Build set of direct dependency paths from go mod edit -json
	let directDepPaths = new Set()
	if (goModEditOutput['Require']) {
		goModEditOutput['Require'].forEach(req => {
			if (!req['Indirect']) {
				directDepPaths.add(req['Path'])
			}
		})
	}
	let matchManifestVersions = getCustom("MATCH_MANIFEST_VERSIONS", "false", opts);
	if(matchManifestVersions === "true") {
		performManifestVersionsCheck(root, rows, manifestContent, parser, requireQuery)
	}

	const mainModule = toPurl(root, "@")
	const license = readLicenseFromManifest(manifest);
	sbom.addRoot(mainModule, license)
	const exhortGoMvsLogicEnabled = getCustom("TRUSTIFY_DA_GO_MVS_LOGIC_ENABLED", "true", opts)
	if(includeTransitive && exhortGoMvsLogicEnabled === "true") {
		rows = getFinalPackagesVersionsForModule(rows, manifest, goBin)
	}
	if (includeTransitive) {
		let currentParent = ""
		let source;
		let rowsWithoutBlankRows = rows.filter(row => row.trim() !== "")
		rowsWithoutBlankRows.forEach(row => {
			if (getParentVertexFromEdge(row) !== currentParent) {
				currentParent = getParentVertexFromEdge(row)
				source = toPurl(currentParent, "@");
			}
			let child = getChildVertexFromEdge(row)
			let target = toPurl(child, "@");
			if (getParentVertexFromEdge(row) === root && !directDepPaths.has(getPackageName(child))) {
				return;
			}
			sbom.addDependency(source, target)

		})
		// at the end, filter out all ignored dependencies including versions.
		sbom.filterIgnoredDepsIncludingVersion(allIgnoredDeps)
		enforceRemovingIgnoredDepsInCaseOfAutomaticVersionUpdate(ignoredDeps, sbom);
	} else {
		let directDependencies = rows.filter(row => row.startsWith(root));
		directDependencies.forEach(pair => {
			let child = getChildVertexFromEdge(pair)
			let target = toPurl(child, "@");
			if(dependencyNotIgnored(ignoredDeps, target)) {
				if (directDepPaths.has(getPackageName(child))) {
					sbom.addDependency(mainModule, target)
				}
			}
		})
		enforceRemovingIgnoredDepsInCaseOfAutomaticVersionUpdate(ignoredDeps, sbom)
	}

	return sbom.getAsJsonString(opts)
}


/**
 * Utility function for creating Purl String

 * @param {string} dependency the name of the artifact, can include a namespace(group) or not - namespace/artifactName.
 * @param {RegExp} delimiter delimiter between name of dependency and version
 * @private
 * @returns {PackageURL|null} PackageUrl Object ready to be used in SBOM
 */
function toPurl(dependency, delimiter) {
	let lastSlashIndex = dependency.lastIndexOf("/");
	let pkg
	if (lastSlashIndex === -1) {
		let splitParts = dependency.split(delimiter);
		pkg = new PackageURL(ecosystem, undefined, splitParts[0], splitParts[1], undefined, undefined)
	} else {
		let namespace = dependency.slice(0, lastSlashIndex)
		let dependencyAndVersion = dependency.slice(lastSlashIndex+1)
		let parts = dependencyAndVersion.split(delimiter);
		if(parts.length === 2 ) {
			pkg = new PackageURL(ecosystem, namespace, parts[0], parts[1], undefined, undefined);
		} else {
			pkg = new PackageURL(ecosystem, namespace, parts[0], defaultMainModuleVersion, undefined, undefined);
		}
	}
	return pkg
}

/** This function gets rows from go mod graph, and go.mod graph, and selecting for all
 * packages the has more than one minor the final versions as selected by golang MVS algorithm.
 * @param {string[]} rows all the rows from go modules dependency tree
 * @param {string} manifestPath the path of the go.mod file
 * @param {string} path to go binary
 * @return {string[]} rows that contains final versions.
 */
function getFinalPackagesVersionsForModule(rows, manifestPath, goBin) {
	let manifestDir = path.dirname(manifestPath)
	let options = {cwd: manifestDir}
	// TODO: determine whether this is necessary
	try {
		invokeCommand(goBin, ['mod', 'download'], options)
		var finalVersionsForAllModules = invokeCommand(goBin, ['list', '-m', 'all'], options).toString()
	} catch(error) {
		throw new Error('failed to list all modules', {cause: error})
	}

	let finalVersionModules = new Map()
	finalVersionsForAllModules.split(getLineSeparatorGolang()).filter(string => string.trim()!== "")
		.filter(string => string.trim().split(" ").length === 2)
		.forEach((dependency) => {
			let dep = dependency.split(" ")
			finalVersionModules[dep[0]] = dep[1]
		})
	let finalVersionModulesArray = new Array()
	rows.filter(string => string.trim()!== "").forEach( module => {
		let child = getChildVertexFromEdge(module)
		let parent = getParentVertexFromEdge(module)
		let parentName = getPackageName(parent)
		let childName = getPackageName(child)
		let parentFinalVersion = finalVersionModules[parentName]
		let childFinalVersion =  finalVersionModules[childName]

		// Handle special cases for go and toolchain modules that aren't in go list -m all
		if (isSpecialGoModule(parentName) || isSpecialGoModule(childName)) {
			// For go and toolchain modules, use the original versions from the graph
			let parentVersion = getVersionOfPackage(parent)
			let childVersion = getVersionOfPackage(child)
			if (parentName !== parent) {
				finalVersionModulesArray.push(`${parentName}@${parentVersion} ${childName}@${childVersion}`)
			} else {
				finalVersionModulesArray.push(`${parentName} ${childName}@${childVersion}`)
			}
		} else {
			// For regular modules, use MVS logic
			if (parentName !== parent) {
				finalVersionModulesArray.push(`${parentName}@${parentFinalVersion} ${childName}@${childFinalVersion}`)
			} else {
				finalVersionModulesArray.push(`${parentName} ${childName}@${childFinalVersion}`)
			}
		}
	})

	return finalVersionModulesArray
}

/**
 *
 * @param {string} fullPackage - full package with its name and version
 * @return {string} package name only
 * @private
 */
function getPackageName(fullPackage) {
	return fullPackage.split("@")[0]
}

/**
 * Check if a module name is a special Go module (go or toolchain)
 * @param {string} moduleName - the module name to check
 * @return {boolean} true if it's a special Go module
 * @private
 */
function isSpecialGoModule(moduleName) {
	return moduleName === 'go' || moduleName === 'toolchain';
}

/**
 *
 * @param {string} fullPackage - full package with its name and version
 * @return {string|undefined} package version only
 * @private
 */
function getVersionOfPackage(fullPackage) {
	let parts = fullPackage.split("@")
	return parts.length > 1 ? parts[1] : undefined
}

function getLineSeparatorGolang() {
	let reg = /\n|\r\n/
	return reg
}
