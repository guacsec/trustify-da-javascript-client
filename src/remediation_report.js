/**
 * Report generator that transforms remediation extractor output into structured
 * markdown for PR bodies, CLI dry-run output, and JSON.
 */

import { SEVERITY_ORDER } from './remediation.js'

/**
 * Generates a formatted report from an array of remediation entries.
 *
 * @param {Array<{purl: string, groupId: string, artifactId: string, currentVersion: string,
 *   fixedInVersion: string, fixedInPurl: string, provider: string, source: string,
 *   advisories: Array<{id: string, url: string}>, severity: string, cves: string[]}>} remediations
 * @param {object} [options]
 * @param {'dependency'|'bundle'} [options.groupBy='dependency'] - grouping strategy
 * @param {'markdown'|'json'} [options.format='markdown'] - output format
 * @param {boolean} [options.dryRun=false] - when true, produces tabular summary
 * @returns {string}
 */
export function generateReport(remediations, options = {}) {
	const { groupBy = 'dependency', format = 'markdown', dryRun = false } = options

	if (!remediations || remediations.length === 0) {
		return format === 'json' ? '[]' : 'No remediations found.'
	}

	if (format === 'json') {
		return JSON.stringify(remediations, null, '\t')
	}

	if (dryRun) {
		return generateDryRunReport(remediations)
	}

	if (groupBy === 'bundle') {
		return generateBundledReport(remediations)
	}

	return generatePerDependencyReport(remediations)
}

/**
 * Generates a per-dependency markdown report with one section per remediation entry.
 * @param {Array<object>} remediations
 * @returns {string}
 */
function generatePerDependencyReport(remediations) {
	const sections = remediations.map(rem => {
		const depName = rem.groupId
			? `${rem.groupId}:${rem.artifactId}`
			: rem.artifactId

		const lines = [
			`## Security Update: ${depName} ${rem.currentVersion} → ${rem.fixedInVersion}`,
			'',
			`**Provider:** ${rem.provider} | **Source:** ${rem.source}`,
			'',
		]

		if (rem.cves && rem.cves.length > 0) {
			lines.push('### Vulnerabilities resolved')
			lines.push('')
			lines.push('| CVE | Severity | Advisory |')
			lines.push('| --- | --- | --- |')
			const advisoryLinks = formatAdvisoryLinks(rem.advisories)
			for (const cve of rem.cves) {
				lines.push(`| ${cve} | ${rem.severity} | ${advisoryLinks} |`)
			}
		}

		return lines.join('\n')
	})

	return sections.join('\n\n')
}

/**
 * Generates a bundled markdown report grouping all remediations by severity.
 * @param {Array<object>} remediations
 * @returns {string}
 */
function generateBundledReport(remediations) {
	const lines = ['# Security Update Summary', '']

	const bySeverity = groupBySeverity(remediations)

	for (const severity of [...SEVERITY_ORDER].reverse()) {
		const group = bySeverity.get(severity)
		if (!group || group.length === 0) {
			continue
		}

		lines.push(`## ${severity}`)
		lines.push('')
		lines.push('| Dependency | Current | Fixed | Provider | CVEs | Advisory |')
		lines.push('| --- | --- | --- | --- | --- | --- |')

		for (const rem of group) {
			const depName = rem.groupId
				? `${rem.groupId}:${rem.artifactId}`
				: rem.artifactId
			const cves = (rem.cves || []).join(', ')
			const advisoryLinks = formatAdvisoryLinks(rem.advisories)
			lines.push(
				`| ${depName} | ${rem.currentVersion} | ${rem.fixedInVersion}`
				+ ` | ${rem.provider} | ${cves} | ${advisoryLinks} |`
			)
		}

		lines.push('')
	}

	return lines.join('\n').trimEnd()
}

/**
 * Generates a tabular dry-run summary of proposed changes.
 * @param {Array<object>} remediations
 * @returns {string}
 */
function generateDryRunReport(remediations) {
	const lines = [
		'Proposed dependency updates:',
		'',
		'| Dependency | Current | Fixed | Severity | Provider |',
		'| --- | --- | --- | --- | --- |',
	]

	for (const rem of remediations) {
		const depName = rem.groupId
			? `${rem.groupId}:${rem.artifactId}`
			: rem.artifactId
		lines.push(
			`| ${depName} | ${rem.currentVersion} | ${rem.fixedInVersion}`
			+ ` | ${rem.severity} | ${rem.provider} |`
		)
	}

	return lines.join('\n')
}

/**
 * Groups remediations by their severity.
 * @param {Array<object>} remediations
 * @returns {Map<string, Array<object>>}
 */
function groupBySeverity(remediations) {
	const map = new Map()
	for (const severity of SEVERITY_ORDER) {
		map.set(severity, [])
	}
	for (const rem of remediations) {
		const sev = rem.severity || 'UNKNOWN'
		if (!map.has(sev)) {
			map.set(sev, [])
		}
		map.get(sev).push(rem)
	}
	return map
}

/**
 * Formats advisory entries into markdown links or plain text.
 * @param {Array<{id: string, url: string}>} advisories
 * @returns {string}
 */
function formatAdvisoryLinks(advisories) {
	if (!advisories || advisories.length === 0) {
		return '-'
	}
	return advisories
		.map(adv => adv.url ? `[${adv.id}](${adv.url})` : adv.id)
		.join(', ')
}

/**
 * Generates a deterministic deduplication key for a remediation entry.
 * Suitable for checking existing PR titles or branch names.
 *
 * @param {object} remediation - a single remediation entry
 * @returns {string} stable key in the form `groupId:artifactId:newVersion`
 */
export function generateDeduplicationKey(remediation) {
	const group = remediation.groupId || ''
	const artifact = remediation.artifactId || ''
	const version = remediation.fixedInVersion || ''
	return `${group}:${artifact}:${version}`
}
