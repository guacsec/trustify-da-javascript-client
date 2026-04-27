// PEP 508 environment marker evaluator.
// Filters Python dependencies by platform/version markers so that e.g.
// "pywin32 ; sys_platform == 'win32'" is excluded on Linux/macOS.
// See https://peps.python.org/pep-0508/#environment-markers

import { execSync } from 'node:child_process'
import os from 'node:os'

let cachedPythonVersion = undefined

function getPythonVersion() {
	if (cachedPythonVersion !== undefined) { return cachedPythonVersion }
	try {
		let out = execSync('python3 -c "import sys; print(f\'{sys.version_info.major}.{sys.version_info.minor}\')"',
			{ timeout: 5000, stdio: ['pipe', 'pipe', 'pipe'] }).toString().trim()
		cachedPythonVersion = out
	} catch {
		cachedPythonVersion = null
	}
	return cachedPythonVersion
}

/**
 * Maps Node.js/OS values to PEP 508 marker variables.
 * Example: on Linux, sys_platform='linux', platform_system='Linux', os_name='posix'
 * @returns {Record<string, string>}
 */
export function getEnvironmentMarkers() {
	let platform = process.platform
	let systemMap = { win32: 'Windows', linux: 'Linux', darwin: 'Darwin' }
	let machine = typeof os.machine === 'function' ? os.machine() : process.arch
	let pyVer = getPythonVersion()
	return {
		sys_platform: platform,
		platform_system: systemMap[platform] || platform,
		os_name: platform === 'win32' ? 'nt' : 'posix',
		platform_machine: machine,
		platform_release: os.release(),
		platform_version: os.version?.() || '',
		python_version: pyVer || '',
		python_full_version: pyVer || '',
		implementation_name: 'cpython',
	}
}

function compareVersions(left, right) {
	let lParts = left.split('.').map(Number)
	let rParts = right.split('.').map(Number)
	let len = Math.max(lParts.length, rParts.length)
	for (let i = 0; i < len; i++) {
		let l = lParts[i] || 0
		let r = rParts[i] || 0
		if (l < r) { return -1 }
		if (l > r) { return 1 }
	}
	return 0
}

// Evaluates a single comparison like sys_platform == 'win32' or python_version >= '3.8'.
// Version-bearing variables (python_version, python_full_version) use numeric comparison;
// all others use string equality. Returns false when the env value is missing.
function evaluateComparison(variable, op, value, env) {
	let envVal = env[variable]
	if (envVal === undefined || envVal === '') {
		return false
	}

	let isVersion = variable.includes('version')
	if (isVersion) {
		let cmp = compareVersions(envVal, value)
		switch (op) {
		case '==': return cmp === 0
		case '!=': return cmp !== 0
		case '>=': return cmp >= 0
		case '<=': return cmp <= 0
		case '>': return cmp > 0
		case '<': return cmp < 0
		case '~=': {
			let parts = value.split('.')
			parts.pop()
			let prefix = parts.join('.')
			return envVal.startsWith(prefix) && cmp >= 0
		}
		default: return true
		}
	}

	switch (op) {
	case '==': return envVal === value
	case '!=': return envVal !== value
	case 'in': return value.split(',').map(s => s.trim()).includes(envVal)
	case 'not in': return !value.split(',').map(s => s.trim()).includes(envVal)
	default: return envVal === value
	}
}

// Parses a single marker comparison into {variable, op, value}.
// Handles both normal and reversed forms:
//   "sys_platform == 'linux'"  → { variable: 'sys_platform', op: '==', value: 'linux' }
//   "'linux' == sys_platform"  → { variable: 'sys_platform', op: '==', value: 'linux' }
function parseAtom(expr) {
	// Normal form: variable op 'value'
	let m = expr.match(/^\s*([\w.]+)\s*(~=|!=|==|>=|<=|>|<|not\s+in|in)\s*["']([^"']*)["']\s*$/)
	if (m) { return { variable: m[1], op: m[2].replace(/\s+/g, ' '), value: m[3] } }

	// Reversed form: 'value' op variable
	let mReverse = expr.match(/^\s*["']([^"']*)['"]\s*(~=|!=|==|>=|<=|>|<|not\s+in|in)\s*([\w.]+)\s*$/)
	if (mReverse) { return { variable: mReverse[3], op: mReverse[2].replace(/\s+/g, ' '), value: mReverse[1] } }

	return null
}

/**
 * Evaluates a full PEP 508 marker expression against the current platform.
 * Example: "sys_platform == 'win32' and python_version >= '3.8'" → false on Linux
 * Empty/missing markers return true (unconditional dependency).
 * @param {string} markerExpr
 * @returns {boolean}
 */
export function evaluateMarker(markerExpr) {
	if (!markerExpr || !markerExpr.trim()) { return true }
	let env = getEnvironmentMarkers()
	return evaluateExpr(markerExpr.trim(), env)
}

function evaluateExpr(expr, env) {
	let orParts = splitLogical(expr, ' or ')
	if (orParts.length > 1) {
		return orParts.some(part => evaluateExpr(part, env))
	}

	let andParts = splitLogical(expr, ' and ')
	if (andParts.length > 1) {
		return andParts.every(part => evaluateExpr(part, env))
	}

	let trimmed = expr.trim()
	if (trimmed.startsWith('(') && trimmed.endsWith(')')) {
		return evaluateExpr(trimmed.slice(1, -1), env)
	}

	let atom = parseAtom(trimmed)
	if (!atom) { return true }

	return evaluateComparison(atom.variable, atom.op, atom.value, env)
}

// Splits an expression by " and " or " or " at the top level, skipping
// separators inside parentheses or quoted strings.
// Example: splitLogical("a == 'x' and (b == 'y' or c == 'z')", " and ")
//        → ["a == 'x'", "(b == 'y' or c == 'z')"]
function splitLogical(expr, sep) {
	let parts = []
	let depth = 0
	let current = ''
	let i = 0
	let quoteChar = null
	while (i < expr.length) {
		let ch = expr[i]
		if (quoteChar) {
			if (ch === quoteChar) { quoteChar = null }
			current += ch
			i++
			continue
		}
		if (ch === '"' || ch === "'") {
			quoteChar = ch
			current += ch
			i++
			continue
		}
		if (ch === '(') { depth++ }
		if (ch === ')') { depth-- }
		if (depth === 0 && expr.substring(i, i + sep.length) === sep) {
			parts.push(current)
			current = ''
			i += sep.length
			continue
		}
		current += ch
		i++
	}
	parts.push(current)
	return parts.filter(p => p.trim())
}
