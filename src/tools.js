import { execFileSync } from "child_process";
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { EOL } from "os";

import { HttpsProxyAgent } from "https-proxy-agent";
import { PackageURL } from "packageurl-js";

export const RegexNotToBeLogged = /TRUSTIFY_DA_(.*_)?TOKEN|ex-.*-token|trust-.*-token/
/**
 *
 * @param {string} key to log its value from environment variables and from opts, if it exists
 * @param {{}} [opts={}] different options of application, if key in it, log it.
 * @param {string }defValue default value of key in case there is no option and environment variable values for key
 */
export function logValueFromObjects(key,opts, defValue) {
	if(key in opts) {
		console.log(`value of option with key ${key} = ${opts[key]} ${EOL}`)
	} else {
		console.log(`key ${key} doesn't exists on opts object ${EOL}`)
	}
	if(key in process.env) {
		console.log(`value of environment variable ${key} = ${process.env[key]} ${EOL}`)
	} else {
		console.log(`environment variable ${key} doesn't exists ${EOL}`)
	}
	console.log(`default value for ${key} = ${defValue} ${EOL}`)
}

/**
 * Utility function returns the value for key from opts, then environment variables,
 * then the supplied default. Values from opts are used only if they are strings.
 * @param {string} key the key to look for in the environment variables and the opts object
 * @param {string|null} [def=null] the value to return if nothing else found
 * @param {{}} [opts={}] the options object to check before the environment
 * @returns {string|null} the value of the key found in the options object, environment, or the
 * 		default supplied
 */
export function getCustom(key, def = null, opts = {}) {
	if (process.env["TRUSTIFY_DA_DEBUG"] === "true" && !key.match(RegexNotToBeLogged)) {
		logValueFromObjects(key, opts, def)
	}
	return key in opts && typeof opts[key] === 'string' ? opts[key] : key in process.env ? process.env[key] : def
}

/**
 * Validates that an executable path does not use directory traversal or relative segments.
 * @param {string} binPath - The executable path to validate.
 * @returns {string} The validated path.
 * @throws {Error} If the path contains '..' segments or is a relative path with separators.
 */
function validateExecutablePath(binPath) {
	if (typeof binPath !== 'string' || binPath.length === 0) {
		throw new Error('Executable path rejected: expected a non-empty string')
	}

	if (binPath.startsWith('./') || binPath.startsWith('.\\')) {
		throw new Error(
			`Executable path rejected: relative paths starting with './' are not allowed: ${binPath}`
		)
	}

	const segments = binPath.split(/[/\\]/)
	if (segments.includes('..')) {
		throw new Error(
			`Executable path rejected: path contains directory traversal segment (..): ${binPath}`
		)
	}

	if ((binPath.includes('/') || binPath.includes('\\')) && !path.isAbsolute(binPath)) {
		throw new Error(
			`Executable path rejected: relative paths are not allowed, use an absolute path or a bare command name: ${binPath}`
		)
	}

	return binPath
}

/**
 * Utility function for looking up custom variable for a binary path.
 * Looks in opts, then environment variables, for a key with TRUSTIFY_DA_x_PATH, where x is an
 * uppercase version of the supplied name. The name is returned if neither contains the key.
 * @param name the binary name to look for, will be returned as value in nothing else found
 * @param {{}} [opts={}] the options object to check before the environment
 * @returns {string|null} the value of the key found in the options object, environment, or the
 * 		original name supplied
 */
export function getCustomPath(name, opts = {}) {
	const resolvedPath = getCustom(`TRUSTIFY_DA_${name.toUpperCase()}_PATH`, name, opts)
	return validateExecutablePath(resolvedPath)
}

/**
 * Utility function for determining whether wrappers for build tools such as gradlew/mvnw should be
 * preferred over invoking the binary directly.
 * @param {string} name - binary for which to search for its wrapper
 * @param {{}} opts - the options object to check before the environment
 * @returns {boolean} whether to prefer the wrapper if exists or not
 */
export function getWrapperPreference(name, opts = {}) {
	return getCustom(`TRUSTIFY_DA_PREFER_${name.toUpperCase()}W`, 'true', opts) === 'true'
}

export function environmentVariableIsPopulated(envVariableName) {
	return envVariableName in process.env && process.env[envVariableName].trim() !== "";
}

/**
 * Utility function for handling spaces in paths on Windows
 * @param {string} path - path to be checked if contains spaces
 * @return {string} a path with all spaces escaped or manipulated so it will be able to be part
 *                  of commands that will be invoked without errors in os' shell.
 */
export function handleSpacesInPath(path) {
	let transformedPath = path
	// if operating system is windows
	if(hasSpaces(path)) {
		transformedPath = `"${path}"`
	}
	return transformedPath
}

/**
 *
 * @param {string} path the path to check if contains spaces
 * @return {boolean} returns true if path contains spaces
 * @private
 */
function hasSpaces(path) {
	return path.trim().includes(" ")
}


/**
 * Utility function for creating Purl String
 * @param name the name of the artifact, can include a namespace(group) or not - namespace/artifactName.
 * @param version the version of the artifact
 * @returns {PackageURL|null} PackageUrl Object ready to be used in SBOM
 */
export function toPurl(type, name, version) {
	let parts = name.split("/");
	var purlNs, purlName;
	if (parts.length === 2) {
		purlNs = parts[0];
		purlName = parts[1];
	} else {
		purlName = parts[0];
	}
	return new PackageURL(type, purlNs, purlName, version, undefined, undefined);
}

/**
 * Utility function for creating Purl Object from a Purl String
 * @param strPurl the Purl String
 * @returns {PackageURL|null} PackageUrl Object ready to be used in SBOM
 */
export function toPurlFromString(strPurl) {
	return PackageURL.fromString(strPurl);
}

/**
 *
 * @param {string} cwd - directory for which to find the root of the git repository.
 */
export function getGitRootDir(cwd) {
	try {
		const root = invokeCommand('git', ['rev-parse', '--show-toplevel'], {cwd: cwd})
		return root.toString().trim()
	} catch (error) {
		return undefined
	}
}

/**
 * Normalize a filesystem path, lowercasing on Windows for case-insensitive comparison.
 *
 * @param {string} thePath
 * @returns {string}
 */
export function normalizePath(thePath) {
	const normalized = path.resolve(thePath).normalize()
	return process.platform === 'win32' ? normalized.toLowerCase() : normalized
}

/**
 * Walk up from `startDir` to `repoRoot` looking for an executable wrapper script.
 *
 * @param {string} startDir - Absolute directory to start from
 * @param {string} wrapperName - Wrapper filename (e.g. `mvnw`, `gradlew`)
 * @param {string} [repoRoot] - Stop boundary (defaults to git root or filesystem root)
 * @returns {string | undefined}
 */
export function traverseForWrapper(startDir, wrapperName, repoRoot = undefined) {
	const currentDir = normalizePath(startDir)
	repoRoot = repoRoot || getGitRootDir(currentDir) || path.parse(currentDir).root
	const wrapperPath = path.join(currentDir, wrapperName)
	try {
		fs.accessSync(wrapperPath, fs.constants.X_OK)
		return wrapperPath
	} catch {
		const rootDir = path.parse(currentDir).root
		if (currentDir === repoRoot || currentDir === rootDir) {
			return undefined
		}
		const parentDir = path.dirname(currentDir)
		if (parentDir === currentDir || parentDir === rootDir) {
			return undefined
		}
		return traverseForWrapper(parentDir, wrapperName, repoRoot)
	}
}

/**
 * Resolve a build-tool binary, preferring a wrapper when configured.
 *
 * @param {string} globalBinary - Global binary name (e.g. `mvn`, `gradle`)
 * @param {string} localWrapper - Wrapper filename (e.g. `mvnw`, `gradlew.bat`)
 * @param {string} startDir - Directory from which to start the wrapper search
 * @param {import('./index.js').Options} [opts={}]
 * @returns {string} Path to the resolved binary
 */
export function resolveBinary(globalBinary, localWrapper, startDir, opts = {}) {
	if (getWrapperPreference(globalBinary, opts)) {
		const wrapper = traverseForWrapper(startDir, localWrapper)
		if (wrapper !== undefined) {
			return wrapper
		}
	}
	return getCustomPath(globalBinary, opts)
}

/** this method invokes command string in a process in a synchronous way.
 * @param {string} bin - the command to be invoked
 * @param {Array<string>} args - the args to pass to the binary
 * @param {import('child_process').ExecFileOptionsWithStringEncoding} [opts={}]
 * @returns {string}
 */
export function invokeCommand(bin, args, opts={}) {
	if (process.platform === 'win32') {
		bin = resolveWindowsCommand(bin, opts.cwd)
		// Native executables take literal argv values; never pre-quote them or enable a shell.
		opts = { ...opts, shell: false, windowsVerbatimArguments: false }
		if (/\.(?:bat|cmd)$/i.test(bin)) {
			// Batch files require cmd.exe. Escape its command string ourselves instead of
			// passing an unescaped argument array with shell:true (Node does not escape it).
			// npm .bin shims reparse arguments, requiring a second layer of caret escaping.
			const isShim = /node_modules[\\/]\.bin[\\/][^\\/]+\.cmd$/i.test(bin)
			const command = [
				escapeWindowsShellToken(path.win32.normalize(bin)),
				...args.map(arg => escapeWindowsShellToken(arg, true, isShim))
			].join(' ')
			bin = process.env.ComSpec || 'cmd.exe'
			args = ['/d', '/v:off', '/s', '/c', `"${command}"`]
			opts = { ...opts, windowsVerbatimArguments: true }
		}
	}

	opts = {
		...opts,
		env: {
			...process.env,
			PATH: process.env.PATH
		}
	};


	// Add maxBuffer option to handle large outputs
	opts = {
		...opts,
		maxBuffer: 10 * 1024 * 1024 // 10MB buffer
	};

	return execFileSync(bin, args, {...{stdio: 'pipe', encoding: 'utf-8'}, ...opts})
}

/** Resolves Windows commands before classifying PATH batch wrappers and local npm shims. */
function resolveWindowsCommand(bin, cwd) {
	const hasExtension = /\.(?:exe|com|bat|cmd)$/i.test(bin)
	if (/\.(?:exe|com)$/i.test(bin) || (hasExtension && path.win32.isAbsolute(bin))) {
		return bin
	}
	cwd = cwd instanceof URL ? fileURLToPath(cwd) : cwd || process.cwd()
	const directories = /[\\/]/.test(bin) ? [''] : ['', ...(process.env.PATH || '').split(';')]
	const extensions = hasExtension
		? ['']
		: (process.env.PATHEXT || '.COM;.EXE;.BAT;.CMD').split(';').filter(Boolean)
	for (const directory of directories) {
		for (const extension of extensions) {
			const candidate = path.win32.resolve(cwd, directory.replace(/^"|"$/g, ''), bin + extension)
			if (fs.statSync(candidate, { throwIfNoEntry: false })?.isFile()) {
				return candidate
			}
		}
	}
	return bin
}

/** Quotes Windows argv values and escapes cmd syntax, including percent and bang expansion. */
function escapeWindowsShellToken(value, argument = false, doubleEscape = false) {
	if (/[\r\n]/.test(value)) {
		throw new Error('Windows batch command inputs must not contain line breaks')
	}
	if (argument) {
		// Windows argv quoting: double backslashes before quotes and the closing quote.
		// A single pass avoids regex backtracking on long runs of backslashes.
		let quoted = '"'
		let backslashes = 0
		for (const character of value) {
			if (character === '\\') {
				backslashes++
				continue
			}
			quoted += '\\'.repeat(character === '"' ? backslashes * 2 + 1 : backslashes) + character
			backslashes = 0
		}
		value = quoted + '\\'.repeat(backslashes * 2) + '"'
	}
	// cmd metacharacters must be escaped even inside quotes: quoting alone permits expansion.
	// This is the cmd token-escaping strategy also used by cross-spawn.
	const metacharacters = /([()\][%!^"`<>&|;, *?])/g
	value = value.replace(metacharacters, '^$1')
	return doubleEscape ? value.replace(metacharacters, '^$1') : value
}


export const TRUSTIFY_DA_TOKEN_HEADER = "trust-da-token";
export const TRUSTIFY_DA_TELEMETRY_ID_HEADER = "telemetry-anonymous-id";
export const TRUSTIFY_DA_SOURCE_HEADER = "trust-da-source"
export const TRUSTIFY_DA_OPERATION_TYPE_HEADER = "trust-da-operation-type"
export const TRUSTIFY_DA_PACKAGE_MANAGER_HEADER = "trust-da-pkg-manager"

/**
 * Adds proxy agent configuration to fetch options if a proxy URL is specified
 * @param {RequestInit} options - The base fetch options
 * @param {import("index.js").Options} opts - The trustify DA options that may contain proxy configuration
 * @returns {RequestInit} The fetch options with proxy agent if applicable
 */
export function addProxyAgent(options, opts) {
	const proxyUrl = getCustom('TRUSTIFY_DA_PROXY_URL', null, opts);
	if (proxyUrl) {
		options.agent = new HttpsProxyAgent(proxyUrl);
	}
	return options;
}

/**
 * Utility function for fetching vendor tokens
 * @param {import("index.js").Options} [opts={}] - optional various options to pass along the application
 * @returns {{}}
 */
export function getTokenHeaders(opts = {}) {
	let headers = {}
	setCustomHeader(TRUSTIFY_DA_TOKEN_HEADER, headers, 'TRUSTIFY_DA_TOKEN', opts);
	setCustomHeader(TRUSTIFY_DA_SOURCE_HEADER, headers, 'TRUSTIFY_DA_SOURCE', opts);
	setCustomHeader(TRUSTIFY_DA_OPERATION_TYPE_HEADER, headers, TRUSTIFY_DA_OPERATION_TYPE_HEADER.toUpperCase().replaceAll("-", "_"), opts);
	setCustomHeader(TRUSTIFY_DA_PACKAGE_MANAGER_HEADER, headers, TRUSTIFY_DA_PACKAGE_MANAGER_HEADER.toUpperCase().replaceAll("-", "_"), opts)
	setCustomHeader(TRUSTIFY_DA_TELEMETRY_ID_HEADER, headers, 'TRUSTIFY_DA_TELEMETRY_ID', opts);

	if (getCustom("TRUSTIFY_DA_DEBUG", null, opts) === "true") {
		console.log("Headers Values to be sent to Trustify DA backend:" + EOL)
		for (const headerKey in headers) {
			if (!headerKey.match(RegexNotToBeLogged)) {
				console.log(`${headerKey}: ${headers[headerKey]}`)
			}
		}
	}
	return headers
}

/**
 *
 * @param {string} headerName - the header name to populate in request
 * @param headers
 * @param {string} optsKey - key in the options object to use the value for
 * @param {import("index.js").Options} [opts={}] - options input object to fetch header values from
 * @private
 */
function setCustomHeader(headerName, headers, optsKey, opts) {
	let customHeaderValue = getCustom(optsKey, null, opts);
	if (customHeaderValue) {
		headers[headerName] = customHeaderValue
	}
}
