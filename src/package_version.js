import fs from "node:fs";
import path from "node:path";
import * as url from "url";

/**
 * Reads this package's version from package.json, resolving the path relative
 * to this module. Works under ESM (node >= 22 import.meta.dirname, older via
 * import.meta.url) and CommonJS (__dirname). Returns undefined if the file
 * cannot be read, so callers never fail on a missing version.
 * @return {string|undefined} the package version, or undefined
 */
export function getPackageVersion() {
	try {
		let dirName = import.meta.dirname
		if (!dirName) {
			dirName = url.fileURLToPath(new URL('.', import.meta.url))
		}
		try {
			if (__dirname) {
				dirName = __dirname
			}
		} catch {
			// __dirname not defined under ESM, continue with fileURLToPath
		}
		const packageJson = JSON.parse(fs.readFileSync(path.join(dirName, "..", "package.json")).toString())
		return packageJson.version
	} catch {
		return undefined
	}
}
