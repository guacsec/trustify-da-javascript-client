import { PackageURL } from 'packageurl-js'

/**
 * Extracts actionable remediation instructions from a DA AnalysisReport response.
 *
 * Walks the provider/source/dependency/issue tree, collects fixedIn and trustedContent
 * remediation data, applies provider priority resolution, and for the same dependency
 * affected by multiple CVEs selects the highest fixedIn version from the highest-priority
 * provider. Dependencies with no remediation data are skipped.
 *
 * @param {object} analysisReport - raw DA AnalysisReport JSON response
 * @param {object} [options] - extraction options
 * @param {string[]} [options.providerPriority] - provider names in descending priority order.
 *   The first entry has the highest priority. Providers not listed share the lowest priority.
 *   When omitted or empty, all providers are treated equally and the highest fix version wins.
 * @returns {Array<{purl: string, groupId: string, artifactId: string, currentVersion: string, fixedInVersion: string, fixedInPurl: string, provider: string, source: string, advisories: Array<{id: string, url: string}>, severity: string, cves: string[]}>}
 */
export function extractRemediations(analysisReport, options = {}) {
	if (!analysisReport || !analysisReport.providers) {
		return []
	}

	const priorityMap = buildPriorityMap(options.providerPriority)
	const remediationsByDep = new Map()
	const rankByDep = new Map()

	for (const [providerName, providerReport] of Object.entries(analysisReport.providers)) {
		const providerRank = priorityMap.get(providerName) ?? 0
		extractFromSources(providerReport, providerName, providerRank, remediationsByDep, rankByDep)
		extractFromRecommendations(providerReport, providerName, providerRank, remediationsByDep, rankByDep)
	}

	return Array.from(remediationsByDep.values())
		.sort((a, b) => a.purl.localeCompare(b.purl))
}

/**
 * Builds a priority lookup map from a provider priority array.
 * First entry gets the highest numeric priority.
 * @param {string[]} [providerPriority]
 * @returns {Map<string, number>}
 */
function buildPriorityMap(providerPriority) {
	const map = new Map()
	if (!providerPriority || providerPriority.length === 0) {
		return map
	}
	for (let i = 0; i < providerPriority.length; i++) {
		map.set(providerPriority[i], providerPriority.length - i)
	}
	return map
}

/**
 * Extracts remediations from the sources/dependencies/issues tree of a provider report.
 * @param {object} providerReport
 * @param {string} providerName
 * @param {number} providerRank - numeric priority rank for this provider
 * @param {Map<string, object>} remediationsByDep - accumulator keyed by dependency PURL
 * @param {Map<string, number>} rankByDep - tracks current winning rank per dependency
 */
function extractFromSources(providerReport, providerName, providerRank, remediationsByDep, rankByDep) {
	if (!providerReport.sources) {
		return
	}

	for (const [sourceName, sourceReport] of Object.entries(providerReport.sources)) {
		if (!sourceReport.dependencies) {
			continue
		}
		for (const dep of sourceReport.dependencies) {
			if (!dep.issues) {
				continue
			}
			for (const issue of dep.issues) {
				processIssueRemediation(
					issue, dep, providerName, sourceName, providerRank, remediationsByDep, rankByDep
				)
			}
		}
	}
}

/**
 * Processes a single issue's remediation data and merges it into the accumulator.
 * @param {object} issue - issue object containing remediation and CVE data
 * @param {object} dep - dependency object containing the ref PURL
 * @param {string} providerName
 * @param {string} sourceName
 * @param {number} providerRank
 * @param {Map<string, object>} remediationsByDep
 * @param {Map<string, number>} rankByDep
 */
function processIssueRemediation(issue, dep, providerName, sourceName, providerRank, remediationsByDep, rankByDep) {
	const fixedInPurl = getFixedInPurl(issue)
	if (!fixedInPurl) {
		return
	}

	const depPurl = dep.ref
	if (!depPurl) {
		return
	}

	let parsedDep
	let parsedFix
	try {
		parsedDep = PackageURL.fromString(depPurl)
		parsedFix = PackageURL.fromString(fixedInPurl)
	} catch {
		return
	}

	const fixedInVersion = parsedFix.version
	if (!fixedInVersion) {
		return
	}

	const cveId = issue.id || issue.cve
	const severity = issue.severity || 'UNKNOWN'
	const advisories = extractAdvisories(issue)

	const existing = remediationsByDep.get(depPurl)

	if (!existing) {
		remediationsByDep.set(depPurl, {
			purl: depPurl,
			groupId: parsedDep.namespace || '',
			artifactId: parsedDep.name,
			currentVersion: parsedDep.version || '',
			fixedInVersion,
			fixedInPurl,
			provider: providerName,
			source: sourceName,
			advisories,
			severity: severity.toUpperCase(),
			cves: cveId ? [cveId] : [],
		})
		rankByDep.set(depPurl, providerRank)
		return
	}

	if (cveId && !existing.cves.includes(cveId)) {
		existing.cves.push(cveId)
	}

	mergeAdvisories(existing.advisories, advisories)

	const existingRank = rankByDep.get(depPurl)

	if (providerRank > existingRank) {
		existing.fixedInVersion = fixedInVersion
		existing.fixedInPurl = fixedInPurl
		existing.provider = providerName
		existing.source = sourceName
		existing.severity = higherSeverity(existing.severity, severity)
		rankByDep.set(depPurl, providerRank)
	} else if (providerRank === existingRank) {
		if (compareVersions(fixedInVersion, existing.fixedInVersion) > 0) {
			existing.fixedInVersion = fixedInVersion
			existing.fixedInPurl = fixedInPurl
			existing.provider = providerName
			existing.source = sourceName
		}
		existing.severity = higherSeverity(existing.severity, severity)
	}
}

/**
 * Extracts remediations from the recommendations section of a provider report.
 * Merges CVEs and advisories into existing entries when present.
 * @param {object} providerReport
 * @param {string} providerName
 * @param {number} providerRank
 * @param {Map<string, object>} remediationsByDep
 * @param {Map<string, number>} rankByDep
 */
function extractFromRecommendations(providerReport, providerName, providerRank, remediationsByDep, rankByDep) {
	if (!providerReport.recommendations || !providerReport.recommendations.dependencies) {
		return
	}

	for (const dep of providerReport.recommendations.dependencies) {
		if (!dep.recommendation || !dep.ref) {
			continue
		}

		const recommendedPurl = dep.recommendation.ref || dep.recommendation
		if (typeof recommendedPurl !== 'string') {
			continue
		}

		let parsedDep
		let parsedRec
		try {
			parsedDep = PackageURL.fromString(dep.ref)
			parsedRec = PackageURL.fromString(recommendedPurl)
		} catch {
			continue
		}

		const fixedInVersion = parsedRec.version
		if (!fixedInVersion) {
			continue
		}

		const depPurl = dep.ref
		const existing = remediationsByDep.get(depPurl)

		if (!existing) {
			remediationsByDep.set(depPurl, {
				purl: depPurl,
				groupId: parsedDep.namespace || '',
				artifactId: parsedDep.name,
				currentVersion: parsedDep.version || '',
				fixedInVersion,
				fixedInPurl: recommendedPurl,
				provider: providerName,
				source: 'recommendation',
				advisories: [],
				severity: 'UNKNOWN',
				cves: [],
			})
			rankByDep.set(depPurl, providerRank)
			continue
		}

		const existingRank = rankByDep.get(depPurl)

		if (providerRank > existingRank) {
			existing.fixedInVersion = fixedInVersion
			existing.fixedInPurl = recommendedPurl
			existing.provider = providerName
			existing.source = 'recommendation'
			rankByDep.set(depPurl, providerRank)
		} else if (providerRank === existingRank) {
			if (compareVersions(fixedInVersion, existing.fixedInVersion) > 0) {
				existing.fixedInVersion = fixedInVersion
				existing.fixedInPurl = recommendedPurl
				existing.provider = providerName
				existing.source = 'recommendation'
			}
		}
	}
}

/**
 * Gets the fixedIn PURL from an issue's remediation, preferring trustedContent.
 * @param {object} issue
 * @returns {string|undefined}
 */
function getFixedInPurl(issue) {
	if (!issue.remediation) {
		return undefined
	}
	if (issue.remediation.trustedContent && issue.remediation.trustedContent.ref) {
		return issue.remediation.trustedContent.ref
	}
	if (issue.remediation.fixedIn) {
		return issue.remediation.fixedIn
	}
	return undefined
}

/**
 * Extracts advisory objects from an issue.
 * @param {object} issue
 * @returns {Array<{id: string, url: string}>}
 */
function extractAdvisories(issue) {
	const advisories = []
	if (issue.remediation && issue.remediation.trustedContent) {
		const tc = issue.remediation.trustedContent
		if (tc.advisory) {
			advisories.push({
				id: tc.advisory.id || tc.advisory,
				url: tc.advisory.url || '',
			})
		}
	}
	if (issue.advisories) {
		for (const adv of issue.advisories) {
			advisories.push({
				id: adv.id || adv,
				url: adv.url || '',
			})
		}
	}
	return advisories
}

/**
 * Merges new advisories into existing list, avoiding duplicates by id.
 * @param {Array<{id: string, url: string}>} existing
 * @param {Array<{id: string, url: string}>} incoming
 */
function mergeAdvisories(existing, incoming) {
	const seen = new Set(existing.map(a => a.id))
	for (const adv of incoming) {
		if (!seen.has(adv.id)) {
			existing.push(adv)
			seen.add(adv.id)
		}
	}
}

/**
 * Compares two version strings segment by segment.
 * Returns positive if a > b, negative if a < b, zero if equal.
 * Falls back to lexicographic comparison for non-numeric segments.
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
function compareVersions(a, b) {
	const partsA = a.split('.')
	const partsB = b.split('.')
	const len = Math.max(partsA.length, partsB.length)
	for (let i = 0; i < len; i++) {
		const segA = partsA[i] || ''
		const segB = partsB[i] || ''
		const numA = Number(segA)
		const numB = Number(segB)
		if (Number.isFinite(numA) && Number.isFinite(numB)) {
			const diff = numA - numB
			if (diff !== 0) return diff
		} else {
			const cmp = segA.localeCompare(segB)
			if (cmp !== 0) return cmp
		}
	}
	return 0
}

export const SEVERITY_ORDER = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

/**
 * Returns the higher of two severity strings, normalized to uppercase.
 * @param {string} a
 * @param {string} b
 * @returns {string}
 */
function higherSeverity(a, b) {
	const upperA = a.toUpperCase()
	const upperB = b.toUpperCase()
	const indexA = SEVERITY_ORDER.indexOf(upperA)
	const indexB = SEVERITY_ORDER.indexOf(upperB)
	return indexA >= indexB ? upperA : upperB
}
