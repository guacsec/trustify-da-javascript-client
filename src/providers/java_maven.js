import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { EOL } from 'os'

import { XMLParser } from 'fast-xml-parser'

import Sbom from '../sbom.js'
import { getCustom } from '../tools.js'

import Base_java, { ecosystem_maven } from "./base_java.js";


/** @typedef {import('../provider').Provider} */

/** @typedef {import('../provider').Provided} Provided */

/** @typedef {{name: string, version: string}} Package */

/** @typedef {{groupId: string, artifactId: string, version: string, scope: string, ignore: boolean}} Dependency */

export default class Java_maven extends Base_java {
	constructor() {
		super('mvn', 'mvnw' + (process.platform === 'win32' ? '.cmd' : ''))
	}

	/**
	 * @param {string} manifestName - the subject manifest name-type
	 * @returns {boolean} - return true if `pom.xml` is the manifest name-type
	 */
	isSupported(manifestName) {
		return 'pom.xml' === manifestName
	}

	/**
	 * @param {string} manifestDir - the directory where the manifest lies
	 */
	validateLockFile() { return true; }

	/**
	 * Provide content and content type for maven-maven stack analysis.
	 * @param {string} manifest - the manifest path or name
	 * @param {{}} [opts={}] - optional various options to pass along the application
	 * @returns {Provided}
	 */
	provideStack(manifest, opts = {}) {
		return {
			ecosystem: ecosystem_maven,
			content: this.#createSbomStackAnalysis(manifest, opts),
			contentType: 'application/vnd.cyclonedx+json'
		}
	}

	/**
	 * Provide content and content type for maven-maven component analysis.
	 * @param {string} manifest - path to the manifest file
	 * @param {{}} [opts={}] - optional various options to pass along the application
	 * @returns {Provided}
	 */
	provideComponent(manifest, opts = {}) {
		return {
			ecosystem: ecosystem_maven,
			content: this.#getSbomForComponentAnalysis(manifest, opts),
			contentType: 'application/vnd.cyclonedx+json'
		}
	}

	/**
	 * Create a Dot Graph dependency tree for a manifest path.
	 * @param {string} manifest - path for pom.xml
	 * @param {{}} [opts={}] - optional various options to pass along the application
	 * @returns {string} the Dot Graph content
	 * @private
	 */
	#createSbomStackAnalysis(manifest, opts = {}) {
		const manifestDir = path.dirname(manifest)
		const mvn = this.selectToolBinary(manifest, opts)
		const mvnArgs = JSON.parse(getCustom('TRUSTIFY_DA_MVN_ARGS', '[]', opts));
		if (!Array.isArray(mvnArgs)) {
			throw new Error(`configured maven args is not an array, is a ${typeof mvnArgs}`)
		}

		// clean maven target
		try {
			this._invokeCommand(mvn, ['-q', 'clean', ...mvnArgs], { cwd: manifestDir })
		} catch (error) {
			throw new Error(`failed to clean maven target`, { cause: error })
		}

		// create dependency graph in a temp file
		let tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'exhort_'))
		let tmpDepTree = path.join(tmpDir, 'mvn_deptree.txt')
		// build initial command (dot outputType is not available for verbose mode)
		let depTreeCmdArgs = ['-q', 'org.apache.maven.plugins:maven-dependency-plugin:3.6.0:tree',
			'-Dscope=compile', '-Dverbose',
			'-DoutputType=text', `-DoutputFile=${tmpDepTree}`]
		// exclude ignored dependencies, exclude format is groupId:artifactId:scope:version.
		// version and scope are marked as '*' if not specified (we do not use scope yet)
		let ignoredDeps = new Array()
		let ignoredArgs = new Array()
		this.#getDependencies(manifest).forEach(dep => {
			if (dep.ignore) {
				ignoredArgs.push(`${dep['groupId']}:${dep['artifactId']}`)
				//version is not reliable because we're not resolving the effective pom
				ignoredDeps.push(this.toPurl(dep.groupId, dep.artifactId))
			}
		})
		if (ignoredArgs.length > 0) {
			depTreeCmdArgs.push(`-Dexcludes=${ignoredArgs.join(',')}`)
		}
		// execute dependency tree command
		try {
			this._invokeCommand(mvn, [...depTreeCmdArgs, ...mvnArgs], { cwd: manifestDir })
		} catch (error) {
			throw new Error(`failed creating maven dependency tree`, { cause: error })
		}
		// read dependency tree from temp file
		let content = fs.readFileSync(tmpDepTree)
		if (process.env["TRUSTIFY_DA_DEBUG"] === "true") {
			console.error("Dependency tree that will be used as input for creating the BOM =>" + EOL + EOL + content.toString())
		}
		let sbom = this.createSbomFileFromTextFormat(content.toString(), ignoredDeps, opts);
		// delete temp file and directory
		fs.rmSync(tmpDir, { recursive: true, force: true })
		// return dependency graph as string
		return sbom
	}

	/**
	 *
	 * @param {String} textGraphList Text graph String of the manifest
	 * @param {[String]} ignoredDeps List of ignored dependencies to be omitted from sbom
	 * @return {String} formatted sbom Json String with all dependencies
	 */
	createSbomFileFromTextFormat(textGraphList, ignoredDeps, opts) {
		let lines = textGraphList.split(EOL);
		// get root component
		let root = lines[0];
		let rootPurl = this.parseDep(root);
		let sbom = new Sbom();
		sbom.addRoot(rootPurl);
		this.parseDependencyTree(root, 0, lines.slice(1), sbom);
		return sbom.filterIgnoredDeps(ignoredDeps).getAsJsonString(opts);
	}

	/**
	 * Create a dependency list for a manifest content.
	 * @param {{}} [opts={}] - optional various options to pass along the application
	 * @returns {[Dependency]} the Dot Graph content
	 * @private
	 */
	#getSbomForComponentAnalysis(manifestPath, opts = {}) {
		const mvn = this.selectToolBinary(manifestPath, opts)
		const mvnArgs = JSON.parse(getCustom('TRUSTIFY_DA_MVN_ARGS', '[]', opts));
		if (!Array.isArray(mvnArgs)) {
			throw new Error(`configured maven args is not an array, is a ${typeof mvnArgs}`)
		}

		const tmpEffectivePom = path.resolve(path.join(path.dirname(manifestPath), 'effective-pom.xml'))

		// create effective pom and save to temp file
		try {
			this._invokeCommand(mvn, ['-q', 'help:effective-pom', `-Doutput=${tmpEffectivePom}`, ...mvnArgs], { cwd: path.dirname(manifestPath) })
		} catch (error) {
			throw new Error(`failed creating maven effective pom`, { cause: error })
		}
		// iterate over all dependencies in original pom and collect all ignored ones
		let ignored = this.#getDependencies(manifestPath).filter(d => d.ignore)
		// iterate over all dependencies and create a package for every non-ignored one
		/** @type [Dependency] */
		let dependencies = this.#getDependencies(tmpEffectivePom)
			.filter(d => !this.#dependencyIn(d, ignored))
		let sbom = new Sbom();
		let rootDependency = this.#getRootFromPom(tmpEffectivePom, manifestPath);
		let purlRoot = this.toPurl(rootDependency.groupId, rootDependency.artifactId, rootDependency.version)
		sbom.addRoot(purlRoot)
		dependencies.forEach(dep => {
			let currentPurl = this.toPurl(dep.groupId, dep.artifactId, dep.version)
			sbom.addDependency(purlRoot, currentPurl)
		})
		fs.rmSync(tmpEffectivePom)

		// return dependencies list
		return sbom.getAsJsonString(opts)
	}

	/**
	 *
	 * @param effectivePomManifest effective pom manifest path
	 * @param originalManifest pom.xml manifest path
	 * @return {Dependency} returns the root dependency for the pom
	 * @private
	 */
	#getRootFromPom(effectivePomManifest) {

		let parser = new XMLParser()
		let buf = fs.readFileSync(effectivePomManifest)
		let effectivePomStruct = parser.parse(buf.toString())
		let pomRoot
		if (effectivePomStruct['project']) {
			pomRoot = effectivePomStruct['project']
		} else { // if there is no project root tag, then it's a multi module/submodules aggregator parent POM
			for (let proj of effectivePomStruct['projects']['project']) {
				// need to choose the aggregate POM and not one of the modules.
				if (proj.packaging && proj.packaging === 'pom') {
					pomRoot = proj
				}
			}
		}
		/** @type Dependency */
		let rootDependency = {
			groupId: pomRoot['groupId'],
			artifactId: pomRoot['artifactId'],
			version: pomRoot['version'],
			scope: '*',
			ignore: false
		}
		return rootDependency
	}

	/**
	 * Get a list of dependencies with marking of dependencies commented with <!--exhortignore-->.
	 * @param {string} manifest - path for pom.xml
	 * @returns {[Dependency]} an array of dependencies
	 * @private
	 */
	#getDependencies(manifest) {
		/** @type [Dependency] */
		let ignored = []
		// build xml parser with options
		let parser = new XMLParser({
			commentPropName: '#comment', // mark comments with #comment
			isArray: (_, jpath) => 'project.dependencies.dependency' === jpath,
			parseTagValue: false
		})
		// read manifest pom.xml file into buffer
		let buf = fs.readFileSync(manifest)
		// parse manifest pom.xml to json
		let pomJson = parser.parse(buf.toString())
		// iterate over all dependencies and chery pick dependencies with a exhortignore comment
		let pomXml;
		// project without modules
		if (pomJson['project']) {
			if (pomJson['project']['dependencies'] !== undefined) {
				pomXml = pomJson['project']['dependencies']['dependency']
			} else {
				pomXml = []
			}
		} else { // project with modules
			pomXml = pomJson['projects']['project'].filter(project => project.dependencies !== undefined).flatMap(project => project.dependencies.dependency)
		}

		pomXml.forEach(dep => {
			let ignore = false
			if (dep['#comment'] && dep['#comment'].includes('exhortignore')) { // #comment is an array or a string
				ignore = true
			}
			if (dep['scope'] !== 'test') {
				ignored.push({
					groupId: dep['groupId'],
					artifactId: dep['artifactId'],
					version: dep['version'] ? dep['version'].toString() : '*',
					scope: '*',
					ignore: ignore
				})
			}
		})
		// return list of dependencies
		return ignored
	}

	/**
	 * Utility function for looking up a dependency in a list of dependencies ignoring the "ignored"
	 * field
	 * @param dep {Dependency} dependency to look for
	 * @param deps {[Dependency]} list of dependencies to look in
	 * @returns boolean true if found dep in deps
	 * @private
	 */
	#dependencyIn(dep, deps) {
		return deps.filter(d => dep.artifactId === d.artifactId && dep.groupId === d.groupId && dep.scope === d.scope).length > 0
	}
}
