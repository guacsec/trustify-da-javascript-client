import Java_gradle from './java_gradle.js';


/** @typedef {import('../provider').Provider} Provider */

/** @typedef {import('../provider').Provided} Provided */

const KOTLIN_DEP_REGEX = /^[a-zA-Z]+\s?\((.*)\)/
const GRADLE_KOTLIN_FILE = "build.gradle.kts"


export default class Java_gradle_kotlin extends Java_gradle {

	/**
	 * @param {string} manifestName - the subject manifest name-type
	 * @returns {boolean} - return true if `pom.xml` is the manifest name-type
	 */

	_getManifestName() {
		return GRADLE_KOTLIN_FILE;
	}

	_parseAliasForLibsNotation(alias) {
		return alias.replace(".", "-").replace(")", "")
	}

	_extractDepToBeIgnored(dep) {
		if(dep.match(KOTLIN_DEP_REGEX)) {
			return KOTLIN_DEP_REGEX.exec(dep)[1]
		}
		return null
	}

}
