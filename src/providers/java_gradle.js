import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { EOL } from 'os'

import { parse as parseToml } from 'smol-toml'

import { readLicenseFile } from '../license/license_utils.js'
import Sbom from '../sbom.js'
import { invokeCommand } from '../tools.js'
import { filterManifestPathsByDiscoveryIgnore, resolveWorkspaceDiscoveryIgnore } from '../workspace.js'

import Base_java, { ecosystem_gradle } from "./base_java.js";



/** @typedef {import('../provider.js').Provider} */

/** @typedef {import('../provider.js').Provided} Provided */

const ROOT_PROJECT_KEY_NAME = "root-project";


const TRUSTIFY_DA_IGNORE_REGEX_LINE = /.*\s?exhortignore\s*$/g
const TRUSTIFY_DA_IGNORE_REGEX = /\/\/\s?exhortignore/

/**
 * Check if the dependency marked for exclusion has libs notation , so if it's true the rest of coordinates( GAV) should be fetched from TOML file.
 * @param {string} depToBeIgnored
 * @return {boolean} returns if the dependency type has library notation or not
 */
function depHasLibsNotation(depToBeIgnored) {
	const regex = new RegExp(":", "g");
	return (depToBeIgnored.trim().startsWith("library(") || depToBeIgnored.trim().includes("libs."))
		&& (depToBeIgnored.match(regex) || []).length <= 1
}

function stripString(depPart) {
	return depPart.replaceAll(/["']/g,"")
}

/**
 * This class provides common functionality for Groovy and Kotlin DSL files.
 */
export default class Java_gradle extends Base_java {
	constructor() {
		super('gradle', 'gradlew' + (process.platform === 'win32' ? '.bat' : ''))
	}

	_getManifestName() {
		throw new Error('implement getManifestName method')
	}

	_parseAliasForLibsNotation() {
		throw new Error('implement parseAliasForLibsNotation method')
	}

	_extractDepToBeIgnored() {
		throw new Error('implement extractDepToBeIgnored method')
	}

	/**
	 * @param {string} manifestName - the subject manifest name-type
	 * @returns {boolean} - return true if the manifest name-type is the supported type (example build.gradle)
	 */

	isSupported(manifestName) {
		return this._getManifestName() === manifestName
	}

	/**
	 * @param {string} manifestDir - the directory where the manifest lies
 	 */
	validateLockFile() { return true; }

	/**
	 * Gradle manifests (build.gradle, build.gradle.kts) have no standard license field.
	 * @param {string} manifestPath - path to manifest
	 * @returns {null}
	 */
	// eslint-disable-next-line no-unused-vars
	readLicenseFromManifest(manifestPath) { return readLicenseFile(manifestPath); }

	/**
	 * Provide content and content type for stack analysis.
	 * @param {string} manifest - the manifest path or name
	 * @param {{}} [opts={}] - optional various options to pass along the application
	 * @returns {Provided}
	 */


	async provideStack(manifest, opts = {}) {
		return {
			ecosystem: ecosystem_gradle,
			content: await this.#createSbomStackAnalysis(manifest, opts),
			contentType: 'application/vnd.cyclonedx+json'
		}
	}

	/**
	 * Provide content and content type for maven-maven component analysis.
	 * @param {string} manifest - path to pom.xml for component report
	 * @param {{}} [opts={}] - optional various options to pass along the application
	 * @returns {Provided}
	 */

	async provideComponent(manifest, opts = {}) {
		return {
			ecosystem: ecosystem_gradle,
			content: await this.#getSbomForComponentAnalysis(manifest, opts),
			contentType: 'application/vnd.cyclonedx+json'
		}
	}

	/**
	 * @param {string} line - the line to parse
	 * @returns {number} the depth of the dependency in the tree starting from 1. -1 if the line is not a dependency.
	 * @private
	 */
	#getIndentationLevel(line) {
		// If it is level 1
		let match = line.match(/^[\\+-]/);
		if (match) {
			return 1;
		}
		// Count the groups of 4 spaces preceded by a pipe or 5 spaces
		match = line.match(/\| {4}| {5}/g);
		if (!match) {return -1;}
		return match.length + 1;
	}


	#prepareLinesForParsingDependencyTree(lines) {
		return lines
			.filter(dep => dep.trim() !== "" && !dep.endsWith(" FAILED"))
			.map(dependency => {
				// Calculate depth from original line
				const depth = this.#getIndentationLevel(dependency);

				// Now process the dependency line
				let processedLine = dependency.replaceAll("|", "");
				processedLine = processedLine.replaceAll(/\\---|\+---/g, "");
				processedLine = processedLine.replaceAll(/:(.*):(.*) -> (.*)$/g, ":$1:$3");
				processedLine = processedLine.replaceAll(/:(.*)\W*->\W*(.*)$/g, ":$1:$2");
				processedLine = processedLine.replaceAll(/(.*):(.*):(.*)$/g, "$1:$2:jar:$3");
				processedLine = processedLine.replaceAll(/(n)$/g, "");
				processedLine = processedLine.replace(/\s*\(\*\)$/, '').trim();

				// Return both the processed line and its depth
				return {
					line: `${processedLine}:compile`,
					depth: depth
				};
			});
	}

	/**
	 * Process the dependency tree and add dependencies to the SBOM
	 * @param {string[]} config - the configuration lines to process
	 * @param {Object} parentPurl - the parent package URL
	 * @param {Sbom} sbom - the SBOM object to add dependencies to
	 * @param {Set} processedDeps - set of already processed dependencies
	 * @param {string} scope - the dependency scope
	 * @param {Map<string, Array<{alg: string, content: string}>>} [hashMap] - map of "group:name@version" to CycloneDX hashes
	 * @private
	 */
	#processDependencyTree(config, parentPurl, sbom, processedDeps, scope, hashMap) {
		const processedLines = this.#prepareLinesForParsingDependencyTree(config);
		let parentStack = [parentPurl];

		for (const {line, depth} of processedLines) {
			if (line) {
				const lastDepth = parentStack.length - 1;
				if (depth <= lastDepth) {
					// Going up - pop parents until we reach the correct level
					parentStack = parentStack.slice(0, depth);
				}

				const currentParent = parentStack[depth - 1];
				const purl = this.parseDep(line);
				purl.scope = scope;

				// Create a unique key for this dependency
				const depKey = `${currentParent.namespace}:${currentParent.name}:${currentParent.version}->${purl.namespace}:${purl.name}:${purl.version}`;

				// Add dependency to SBOM if not already processed
				if (!processedDeps.has(depKey)) {
					processedDeps.add(depKey);
					sbom.addDependency(currentParent, purl, scope, hashMap?.get(purl.toString()));
				}
				parentStack.push(purl);
			}
		}
	}

	/**
	 * Create a Dot Graph dependency tree for a manifest path.
	 * @param {string} manifest - path for pom.xml
	 * @param {{}} [opts={}] - optional various options to pass along the application
	 * @returns {string} the Dot Graph content
	 * @private
	 */
	#buildSbom(content, properties, manifestPath, opts = {}, hashMap) {
		let sbom = new Sbom();
		let root = `${properties.group}:${properties[ROOT_PROJECT_KEY_NAME].match(/Root project '(.+)'/)[1]}:jar:${properties.version}`
		let rootPurl = this.parseDep(root)
		const license = this.readLicenseFromManifest(manifestPath);
		sbom.addRoot(rootPurl, license)
		let ignoredDeps = this.#getIgnoredDeps(manifestPath);

		const [runtimeConfig, compileConfig] = this.#extractConfigurations(content);

		const processedDeps = new Set();

		this.#processDependencyTree(runtimeConfig, rootPurl, sbom, processedDeps, 'required', hashMap);
		this.#processDependencyTree(compileConfig, rootPurl, sbom, processedDeps, 'optional', hashMap);

		return sbom.filterIgnoredDepsIncludingVersion(ignoredDeps).getAsJsonString(opts);
	}

	/**
	 * Create a Dot Graph dependency tree for a manifest path.
	 * @param {string} manifest - path for pom.xml
	 * @param {{}} [opts={}] - optional various options to pass along the application
	 * @returns {string} the Dot Graph content
	 * @private
	 */
	async #createSbomStackAnalysis(manifest, opts = {}) {
		let content = this.#getDependencies(manifest, opts)
		let properties = this.#extractProperties(manifest, opts)
		let hashMap = await this.parseGradleHashes(manifest, opts)
		// read dependency tree from temp file
		if (process.env["TRUSTIFY_DA_DEBUG"] === "true") {
			console.log("Dependency tree that will be used as input for creating the BOM =>" + EOL + EOL + content)
		}
		let sbom = this.#buildSbom(content, properties, manifest, opts, hashMap)
		return sbom
	}

	/**
	 *
	 * @param {string} manifestPath - path to build.gradle.
	 * @param {Object} opts - contains various options settings from client.
	 * @return {{Object}} an object that contains all gradle properties
	 */
	#extractProperties(manifestPath, opts) {
		let properties = {}
		let propertiesContent = this.#getProperties(manifestPath, opts)
		let regExpMatchArray = propertiesContent.match(/([^\n:]+):[\t ]*(.*)/g);
		for (let i = 0; i < regExpMatchArray.length - 1; i++) {
			let parts = regExpMatchArray[i].split(":");
			properties[parts[0].trim()] = parts[1].trim()
		}
		let regExpMatchArray1 = propertiesContent.match(/Root project '(.+)'/);
		if (regExpMatchArray1[0]) {
			properties[ROOT_PROJECT_KEY_NAME] = regExpMatchArray1[0]
		}
		return properties;
	}

	/**
	 *
	 * @param manifestPath - path to build.gradle
	 * @param {Object} opts - contains various options settings from client.
	 * @return {string} string content of the properties
	 */
	#getProperties(manifestPath, opts) {
		let gradle = this.selectToolBinary(manifestPath, opts)
		try {
			let properties = this._invokeCommand(gradle, ['properties'], {cwd: path.dirname(manifestPath)})
			return properties.toString()
		} catch (error) {
			throw new Error(`Couldn't get properties of ${this._getManifestName()} file , Error message returned from gradle binary => ${EOL} ${error.message}`)
		}
	}

	/**
	 * Create a dependency list for a manifest content.
	 * @param {{}} [opts={}] - optional various options to pass along the application
	 * @returns {string} - sbom string of the direct dependencies of build.gradle
	 * @private
	 */
	async #getSbomForComponentAnalysis(manifestPath, opts = {}) {
		let content = this.#getDependencies(manifestPath, opts)
		let properties = this.#extractProperties(manifestPath, opts)
		let hashMap = await this.parseGradleHashes(manifestPath, opts)

		let sbom = this.#buildDirectDependenciesSbom(content, properties, manifestPath, opts, hashMap)
		return sbom

	}

	/**
	 * Get a list of dependencies from gradle dependencies command.
	 * @param {string} manifest - path for build.gradle
	 * @returns {string} Multi-line string contain all dependencies from gradle dependencies command
	 * @private
	 */

	#getDependencies(manifest, opts={}) {
		const gradle = this.selectToolBinary(manifest, opts)
		try {
			const commandResult = this._invokeCommand(gradle, ['dependencies'], {cwd: path.dirname(manifest)})
			return commandResult.toString()
		} catch (error) {
			throw new Error(`Couldn't run gradle dependencies command, error message returned from gradle binary => ${EOL} ${error.message}`)
		}
	}

	/**
	 * Hash a file using SHA-256 with streaming to handle large files efficiently.
	 * @param {string} filePath - path to the file to hash
	 * @returns {Promise<string>} hex-encoded SHA-256 digest
	 * @private
	 */
	#hashFileStream(filePath) {
		return new Promise((resolve, reject) => {
			const hash = crypto.createHash('sha256')
			const stream = fs.createReadStream(filePath)
			stream.on('data', chunk => hash.update(chunk))
			stream.on('end', () => resolve(hash.digest('hex')))
			stream.on('error', reject)
		})
	}

	/**
	 * Compute SHA-256 hashes for the resolved artifacts of a Gradle manifest.
	 *
	 * Rather than scanning the local Gradle cache, this asks Gradle itself for
	 * the resolved artifact files via an init script (mirroring the pattern used
	 * by {@link discoverGradleSubprojects}), then hashes each file with the
	 * Node.js `crypto` module. The result is keyed by the canonical PURL string
	 * built via {@link Base_java#toPurl} — the same builder {@link parseDep} uses
	 * for the lookup — so the stored key and the lookup key cannot drift.
	 *
	 * Degrades gracefully: if Gradle cannot be invoked, the init script fails, or
	 * an artifact has no readable file (e.g. BOM/`platform()` dependencies), the
	 * hash for that component is omitted rather than throwing. A warning is emitted
	 * on every degradation path so incomplete hash coverage is visible even without
	 * `TRUSTIFY_DA_DEBUG` (mirroring the pip/cargo providers).
	 *
	 * @param {string} manifest - path to build.gradle[.kts]
	 * @param {{}} [opts={}] - optional various options to pass along the application
	 * @returns {Promise<Map<string, Array<{alg: string, content: string}>>>} map of canonical PURL string to CycloneDX hashes
	 */
	async parseGradleHashes(manifest, opts = {}) {
		const hashMap = new Map()
		const debug = process.env["TRUSTIFY_DA_DEBUG"] === "true"

		let gradle
		try {
			gradle = this.selectToolBinary(manifest, opts)
		} catch (error) {
			console.warn(`Gradle could not be invoked to compute artifact hashes, SBOM will be generated without hashes: ${error.stack || error.message}`)
			return hashMap
		}

		const initScriptPath = path.join(os.tmpdir(), `da-list-hashes-${crypto.randomUUID()}.gradle`)
		try {
			fs.writeFileSync(initScriptPath, GRADLE_HASH_INIT_SCRIPT)
			let output
			try {
				output = this._invokeCommand(gradle, [
					'-q', '--no-daemon',
					'--init-script', initScriptPath,
					'daListHashes',
				], { cwd: path.dirname(manifest) })
			} catch (error) {
				console.warn(`Gradle hash init script failed, SBOM will be generated without hashes: ${error.stack || error.message}`)
				return hashMap
			}

			let attempted = 0
			let missed = 0
			for (const { id, file } of parseGradleHashScriptOutput(output.toString())) {
				const coord = parseComponentId(id)
				if (!coord) {
					continue
				}
				// Build the key with the same canonical PURL builder parseDep uses for
				// the lookup, so the stored key and the lookup key cannot drift.
				const key = this.toPurl(coord.group, coord.name, coord.version).toString()
				if (hashMap.has(key)) {
					continue
				}
				attempted++
				try {
					const digest = await this.#hashFileStream(file)
					hashMap.set(key, [{ alg: 'SHA-256', content: digest }])
				} catch (error) {
					// artifact file missing/unreadable — omit the hash for this component
					missed++
					if (debug) {
						console.error(`Gradle hash: could not read artifact ${file} => ${error.message}`)
					}
				}
			}
			if (missed > 0) {
				console.warn(`Gradle hash: ${missed} of ${attempted} resolved artifacts could not be read, SBOM will be generated without hashes for those components`)
			}
		} catch (error) {
			// Unexpected failure (e.g. a programming error) is degraded to keep SBOM
			// generation working, but the error is surfaced so it is not mistaken
			// for ordinary graceful degradation.
			console.warn(`Gradle artifact hashing failed, SBOM will be generated without hashes: ${error.stack || error.message}`)
			return hashMap
		} finally {
			try { fs.unlinkSync(initScriptPath) } catch { /* ignore */ }
		}

		return hashMap
	}

	/**
	 * Extracts runtime and compile configurations from the dependency tree
	 * @param {string} content - the dependency tree content
	 * @returns {[string[], string[]]} tuple of [runtimeConfig, compileConfig]
	 * @private
	 */
	#extractConfigurations(content) {
		const lines = content.split(EOL);
		const configs = {
			runtimeClasspath: [],
			compileClasspath: []
		};
		let currentConfig = null;
		let collecting = false;

		for (const line of lines) {
			// Check for configuration start
			if (line.startsWith('runtimeClasspath')) {
				currentConfig = 'runtimeClasspath';
				collecting = true;
				continue;
			} else if (line.startsWith('compileClasspath')) {
				currentConfig = 'compileClasspath';
				collecting = true;
				continue;
			}

			// If we're not collecting or no config is set, skip
			if (!collecting || !currentConfig) {continue;}

			// Check for end of configuration
			if (line.trim() === '') {
				collecting = false;
				currentConfig = null;
				continue;
			}

			// Add line to current configuration
			configs[currentConfig].push(line);
		}

		return [configs.runtimeClasspath, configs.compileClasspath];
	}

	/**
	 *
	 * @param content {string} - content of the dependency tree received from gradle dependencies command
	 * @param properties {Object} - properties of the gradle project.
	 * @return {string} return sbom json string of the build.gradle manifest file
	 */
	#buildDirectDependenciesSbom(content, properties, manifestPath, opts = {}, hashMap) {
		let sbom = new Sbom();
		let root = `${properties.group}:${properties[ROOT_PROJECT_KEY_NAME].match(/Root project '(.+)'/)[1]}:jar:${properties.version}`
		let rootPurl = this.parseDep(root)
		const license = this.readLicenseFromManifest(manifestPath);
		sbom.addRoot(rootPurl, license)
		let ignoredDeps = this.#getIgnoredDeps(manifestPath);

		const [runtimeConfig, compileConfig] = this.#extractConfigurations(content);

		let directDependencies = new Map();
		this.#processDirectDependencies(runtimeConfig, directDependencies, 'required');
		this.#processDirectDependencies(compileConfig, directDependencies, 'optional');

		directDependencies.forEach((scope, dep) => {
			const purl = this.parseDep(dep);
			purl.scope = scope;
			sbom.addDependency(rootPurl, purl, scope, hashMap?.get(purl.toString()));
		});

		return sbom.filterIgnoredDepsIncludingVersion(ignoredDeps).getAsJsonString(opts);
	}

	#processDirectDependencies(config, directDependencies, scope) {
		const lines = this.#prepareLinesForParsingDependencyTree(config);
		lines.forEach(({line, depth}) => {
			if (depth === 1 && !directDependencies.has(line)) {
				directDependencies.set(line, scope);
			}
		});
	}

	/**
	 * This method gets build.gradle manifest, and extracts from it all artifacts marks for exclusion using an //exhortignore comment.
	 * @param {string} manifestPath the build.gradle manifest path
	 * @return {string[]} an array with all dependencies to ignore - contains 'stringified' purls as elements
	 * @private
	 */
	#getIgnoredDeps(manifestPath) {
		let buildGradleLines = fs.readFileSync(manifestPath).toString().split(EOL)
		let ignored =
			buildGradleLines.filter(line => line && line.match(TRUSTIFY_DA_IGNORE_REGEX_LINE))
				.map(line => line.indexOf("/*") === -1 ? line : line.substring(0, line.indexOf("/*")))
				.map(line => line.trim().substring(0, line.trim().search(TRUSTIFY_DA_IGNORE_REGEX)))

		let depsToIgnore = new Array
		ignored.forEach(depToBeIgnored => {
			let ignoredDepInfo
			if (depHasLibsNotation(depToBeIgnored)) {
				ignoredDepInfo = this.#getDepFromLibsNotation(depToBeIgnored, manifestPath);
			} else {
				ignoredDepInfo = this.#getDependencyFromStringOrMapNotation(depToBeIgnored)
			}
			if (ignoredDepInfo) {
				depsToIgnore.push(ignoredDepInfo)
			}
		})
		return depsToIgnore
	}

	#getDepFromLibsNotation(depToBeIgnored, manifestPath) {
		// Extract everything after "libs."
		let alias = depToBeIgnored.substring(depToBeIgnored.indexOf("libs.") + "libs.".length).trim()
		alias = this._parseAliasForLibsNotation(alias)
		// Read and parse the TOML file
		let pathOfToml = path.join(path.dirname(manifestPath),"gradle","libs.versions.toml");
		const tomlString = fs.readFileSync(pathOfToml).toString()
		let tomlObject = parseToml(tomlString)
		let groupPlusArtifactObject = tomlObject.libraries[alias]
		let parts = groupPlusArtifactObject.module.split(":");
		let groupId = parts[0]
		let artifactId = parts[1]
		let versionRef = groupPlusArtifactObject.version.ref
		let version = tomlObject.versions[versionRef]
		return groupId && artifactId && version ? this.toPurl(groupId,artifactId,version).toString() : undefined

	}

	/**
	 * Gets a dependency line of type string/map notation from build.gradle, extract the coordinates from it and returns string purl
	 * @param depToBeIgnored
	 * @return {string|undefined} string of a purl format of the extracted coordinates.
	 */
	#getDependencyFromStringOrMapNotation(depToBeIgnored) {
		// dependency line is of form MapNotation
		if (depToBeIgnored.includes("group:") && depToBeIgnored.includes("name:") && depToBeIgnored.includes("version:")) {
			let matchedKeyValues = depToBeIgnored.match(/(group|name|version):\s*['"](.*?)['"]/g)
			let coordinates = {}
			for (let coordinatePairIndex in matchedKeyValues) {
				let keyValue = matchedKeyValues[coordinatePairIndex].split(":");
				coordinates[keyValue[0].trim()] = stripString(keyValue[1].trim())
			}
			return this.toPurl(coordinates.group,coordinates.name,coordinates.version).toString()

		// 	Dependency line is of form String Notation
		} else {
			let depParts
			const depToBeIgnoredMatch = this._extractDepToBeIgnored(depToBeIgnored)
			if(depToBeIgnoredMatch) {
				depParts = depToBeIgnoredMatch.split(":");
			} else {
				depParts = depToBeIgnored.split(":");
			}
			if(depParts.length === 3) {
				let groupId = stripString(depParts[0])
				let artifactId = stripString(depParts[1])
				let version = stripString(depParts[2])
				return this.toPurl(groupId,artifactId,version).toString()
			}

		}

		return undefined
	}
}

const DEFAULT_GRADLE_DISCOVERY_IGNORE = [
	'**/build/**',
	'**/.gradle/**',
]

/** Gradle init script that emits structured project listing. */
const GRADLE_INIT_SCRIPT = `allprojects {
    task daListProjects {
        doLast {
            println "::DA_PROJECT::\${project.path}::\${project.projectDir}"
        }
    }
}
`

/**
 * Gradle init script that emits, per resolved module artifact, a structured line
 * of the form `::DA_HASH::group:name:version::/absolute/file/path`. It obtains
 * files from Gradle's resolution API (the same approach as the CycloneDX Gradle
 * plugin) so it is robust to cache-layout changes and correctly reports
 * classifiers and non-jar artifacts. Uses a lenient artifact view so
 * unresolved/fileless artifacts are skipped rather than failing the build.
 */
const GRADLE_HASH_INIT_SCRIPT = `allprojects {
    task daListHashes {
        doLast {
            configurations.findAll { it.canBeResolved }.each { cfg ->
                cfg.incoming.artifactView { lenient = true }.artifacts.each { artifact ->
                    def cid = artifact.id.componentIdentifier
                    if (cid instanceof org.gradle.api.artifacts.component.ModuleComponentIdentifier) {
                        println "::DA_HASH::\${cid.group}:\${cid.module}:\${cid.version}::\${artifact.file.absolutePath}"
                    }
                }
            }
        }
    }
}
`

/**
 * Discover all build.gradle[.kts] manifest paths in a Gradle multi-project build.
 * Uses a custom init script to get structured project listing.
 *
 * @param {string} workspaceRoot - Absolute or relative path to workspace root (must contain settings.gradle[.kts])
 * @param {import('../index.js').Options} [opts={}]
 * @returns {Promise<string[]>} Paths to build.gradle[.kts] files (absolute)
 */
export async function discoverGradleSubprojects(workspaceRoot, opts = {}) {
	const root = path.resolve(workspaceRoot)
	const hasSettings = fs.existsSync(path.join(root, 'settings.gradle'))
		|| fs.existsSync(path.join(root, 'settings.gradle.kts'))

	if (!hasSettings) {
		return []
	}

	const manifestPaths = []

	const rootBuildKts = path.join(root, 'build.gradle.kts')
	const rootBuild = path.join(root, 'build.gradle')
	const rootManifest = fs.existsSync(rootBuildKts) ? rootBuildKts : fs.existsSync(rootBuild) ? rootBuild : null
	if (rootManifest) {
		manifestPaths.push(rootManifest)
	}

	let gradleBin
	try {
		gradleBin = new Java_gradle().selectToolBinary(rootManifest || rootBuild, opts)
	} catch {
		const ignorePatterns = [...resolveWorkspaceDiscoveryIgnore(opts), ...DEFAULT_GRADLE_DISCOVERY_IGNORE]
		return filterManifestPathsByDiscoveryIgnore(manifestPaths, root, ignorePatterns)
	}

	const initScriptPath = path.join(os.tmpdir(), `da-list-projects-${crypto.randomUUID()}.gradle`)
	try {
		fs.writeFileSync(initScriptPath, GRADLE_INIT_SCRIPT)
		let output
		try {
			output = invokeCommand(gradleBin, [
				'-q', '--no-daemon',
				'--init-script', initScriptPath,
				'daListProjects',
			], { cwd: root })
		} catch {
			const ignorePatterns = [...resolveWorkspaceDiscoveryIgnore(opts), ...DEFAULT_GRADLE_DISCOVERY_IGNORE]
			return filterManifestPathsByDiscoveryIgnore(manifestPaths, root, ignorePatterns)
		}

		const projects = parseGradleInitScriptOutput(output.toString())
		for (const proj of projects) {
			if (proj.path === ':') {
				continue
			}
			const projDir = path.resolve(proj.dir)
			const buildKts = path.join(projDir, 'build.gradle.kts')
			const buildGroovy = path.join(projDir, 'build.gradle')
			if (fs.existsSync(buildKts)) {
				manifestPaths.push(buildKts)
			} else if (fs.existsSync(buildGroovy)) {
				manifestPaths.push(buildGroovy)
			}
		}
	} finally {
		try { fs.unlinkSync(initScriptPath) } catch { /* ignore */ }
	}

	const ignorePatterns = [...resolveWorkspaceDiscoveryIgnore(opts), ...DEFAULT_GRADLE_DISCOVERY_IGNORE]
	return filterManifestPathsByDiscoveryIgnore(manifestPaths, root, ignorePatterns)
}

/**
 * Parse the structured output from the Gradle init script.
 *
 * @param {string} raw - Raw stdout from gradle
 * @returns {{ path: string, dir: string }[]}
 */
export function parseGradleInitScriptOutput(raw) {
	const projects = []
	for (const rawLine of raw.split('\n')) {
		const line = rawLine.trimEnd()
		if (!line.startsWith('::DA_PROJECT::')) {
			continue
		}
		const prefix = '::DA_PROJECT::'
		const remainder = line.substring(prefix.length)
		const lastSep = remainder.lastIndexOf('::')
		if (lastSep < 0) {
			continue
		}
		const projPath = remainder.substring(0, lastSep)
		const dir = remainder.substring(lastSep + 2)
		if (projPath && dir) {
			projects.push({ path: projPath, dir })
		}
	}
	return projects
}

/**
 * Parse the structured output from the Gradle hash init script.
 * Each recognised line has the form `::DA_HASH::group:name:version::<file-path>`.
 *
 * @param {string} raw - Raw stdout from gradle
 * @returns {{ id: string, file: string }[]} component id (`group:name:version`) and absolute artifact file path
 */
export function parseGradleHashScriptOutput(raw) {
	const artifacts = []
	for (const rawLine of raw.split('\n')) {
		const line = rawLine.trimEnd()
		if (!line.startsWith('::DA_HASH::')) {
			continue
		}
		const prefix = '::DA_HASH::'
		const remainder = line.substring(prefix.length)
		const lastSep = remainder.lastIndexOf('::')
		if (lastSep < 0) {
			continue
		}
		const id = remainder.substring(0, lastSep)
		const file = remainder.substring(lastSep + 2)
		if (id && file) {
			artifacts.push({ id, file })
		}
	}
	return artifacts
}

/**
 * Parse a Gradle module component id (`group:name:version`) into its coordinate
 * parts. The caller builds the canonical PURL key from these parts using the same
 * builder {@link parseDep} uses, so the stored key and the lookup key cannot drift.
 *
 * @param {string} id - the Gradle component id
 * @returns {{group: string, name: string, version: string}|null} the parsed coordinate, or null when the id is malformed
 */
export function parseComponentId(id) {
	const parts = id.split(':')
	if (parts.length < 3) {
		return null
	}
	const [group, name, version] = parts
	if (!group || !name || !version) {
		return null
	}
	return { group, name, version }
}
