import Java_gradle from './java_gradle.js';

/** @typedef {import('../provider').Provider} Provider */

/** @typedef {import('../provider').Provided} Provided */

const GROOVY_DEP_REGEX = /^[a-zA-Z]+\s/
const GRADLE_GROOVY_FILE = "build.gradle"

export default class Java_gradle_groovy extends Java_gradle {

	_getManifestName() {
		return GRADLE_GROOVY_FILE;
	}

	_parseAliasForLibsNotation(alias) {
		return alias.replace(".", "-")
	}

	_extractDepToBeIgnored(dep) {
		if(dep.match(GROOVY_DEP_REGEX)) {
			return dep.split(" ")[1]
		}
		return null
	}
}
