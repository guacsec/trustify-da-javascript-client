import fs from 'fs'
import os from 'os'
import path from 'path'

/** Directory holding deterministic stand-in artifact files whose content is hashed by the provider. */
export const HASH_FIXTURE_DIR = path.join(os.tmpdir(), 'da-gradle-hash-fixtures')

/**
 * Extract a superset of `group:name:version` coordinates from a gradle dependency tree.
 * Mirrors the tree-glyph stripping done by the provider so artifact names with hyphens
 * are preserved; extra coordinates are harmless because the provider only looks up real ones.
 * @param {string} depTree - the `gradle dependencies` output
 * @returns {string[]} unique `group:name:version` coordinates
 */
export function extractCoordinates(depTree) {
	const coords = new Set()
	for (const raw of depTree.split(/\r?\n/)) {
		const line = raw.replaceAll('|', ' ').replace(/\\---|\+---/g, ' ').trim()
		if (!line || line.startsWith('No dependencies') || line.startsWith('Root project')) {
			continue
		}
		const m = line.match(/^([\w.-]+):([\w.-]+):([\w.-]+)(?:\s*->\s*([\w.-]+))?/)
		if (m) {
			const version = m[4] || m[3]
			coords.add(`${m[1]}:${m[2]}:${version}`)
		}
	}
	return [...coords]
}

/**
 * Ensure a deterministic stand-in artifact file exists for a coordinate and return its path.
 * The file content is the coordinate itself, so the SHA-256 the provider computes is stable.
 * @param {string} coord - a `group:name:version` coordinate
 * @returns {string} absolute path to the artifact file
 */
export function artifactFileFor(coord) {
	fs.mkdirSync(HASH_FIXTURE_DIR, { recursive: true })
	const p = path.join(HASH_FIXTURE_DIR, coord.replace(/[^\w.-]/g, '_') + '.jar')
	if (!fs.existsSync(p)) {
		fs.writeFileSync(p, coord)
	}
	return p
}

/**
 * Build the `::DA_HASH::group:name:version::<file>` init-script output for a dependency tree.
 * @param {string} depTree - the `gradle dependencies` output
 * @param {(coord: string) => string|null} [fileFor=artifactFileFor] - resolves a coordinate to an artifact path; return null to omit the line
 * @returns {string} the mocked init-script stdout
 */
export function buildHashScriptOutput(depTree, fileFor = artifactFileFor) {
	return extractCoordinates(depTree)
		.map(c => {
			const file = fileFor(c)
			return file ? `::DA_HASH::${c}::${file}` : null
		})
		.filter(Boolean)
		.join('\n')
}

/**
 * Stub for `_invokeCommand` that answers `dependencies`, `properties`, and the
 * `daListHashes` init-script task used to compute artifact hashes.
 * @param {string[]} args - the args passed to the gradle binary
 * @param {string} dependencyTreeTextContent - mocked `gradle dependencies` output
 * @param {string} gradleProperties - mocked `gradle properties` output
 * @param {string} [hashScriptOutput] - mocked `daListHashes` output (defaults to hashes for the whole tree)
 * @returns {string} the mocked stdout for the requested gradle invocation
 */
export function getStubbedResponse(args, dependencyTreeTextContent, gradleProperties, hashScriptOutput) {
	if (args.includes("daListHashes")) {
		return hashScriptOutput !== undefined ? hashScriptOutput : buildHashScriptOutput(dependencyTreeTextContent)
	} else if (args.includes("dependencies")) {
		return dependencyTreeTextContent
	} else if (args.includes("properties")) {
		return gradleProperties
	}
	return ''
}

/**
 * Install a mocked `_invokeCommand` on the Base_java prototype for a provider.
 * @param {object} provider - the gradle provider instance
 * @param {string} depTree - mocked dependency tree output
 * @param {string} props - mocked properties output
 * @param {string} [hashScriptOutput] - optional override for the `daListHashes` output
 */
export function mockInvokeCommand(provider, depTree, props, hashScriptOutput) {
	const mockedExecFunction = function (bin, args) {
		return getStubbedResponse(args, depTree, props, hashScriptOutput);
	}
	Object.getPrototypeOf(Object.getPrototypeOf(provider))._invokeCommand = mockedExecFunction
}

/**
 * Remove the stand-in artifact files created by {@link artifactFileFor}. Call from
 * `suiteTeardown` so long-lived CI agents do not accumulate temp artifacts.
 */
export function cleanupHashFixtures() {
	fs.rmSync(HASH_FIXTURE_DIR, { recursive: true, force: true })
}
