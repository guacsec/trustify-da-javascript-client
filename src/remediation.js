import { PackageURL } from 'packageurl-js'

/**
 * Provider priority levels. Higher value = higher priority.
 * Lightwell rebuilt packages (.rhlw-) > Red Hat advisories (.redhat-) > generic.
 */
const PROVIDER_PRIORITY = {
	lightwell: 3,
	redhat: 2,
	generic: 1,
}

/**
 * Extracts actionable remediation instructions from a DA AnalysisReport response.
 *
 * Walks the provider/source/dependency/issue tree, collects fixedIn and trustedContent
 * remediation data, applies provider priority resolution, and for the same dependency
 * affected by multiple CVEs selects the highest fixedIn version from the highest-priority
 * provider. Dependencies with no remediation data are skipped.
 *
 * @param {object} analysisReport - raw DA AnalysisReport JSON response
 * @returns {Array<{purl: string, groupId: string, artifactId: string, currentVersion: string, fixedInVersion: string, fixedInPurl: string, provider: string, source: string, advisories: Array<{id: string, url: string}>, severity: string, cves: string[]}>}
 */
export function extractRemediations(analysisReport) {
	if (!analysisReport || !analysisReport.providers) {
		return []
	}

	const remediationsByDep = new Map()

	for (const [providerName, providerReport] of Object.entries(analysisReport.providers)) {
		extractFromSources(providerReport, providerName, remediationsByDep)
		extractFromRecommendations(providerReport, providerName, remediationsByDep)
	}

	return Array.from(remediationsByDep.values())
		.map(entry => {
			const cleaned = { ...entry }
			delete cleaned._priority
			return cleaned
		})
		.sort((a, b) => a.purl.localeCompare(b.purl))
}

/**
 * Extracts remediations from the sources/dependencies/issues tree of a provider report.
 * @param {object} providerReport
 * @param {string} providerName
 * @param {Map<string, object>} remediationsByDep - accumulator keyed by dependency PURL
 */
function extractFromSources(providerReport, providerName, remediationsByDep) {
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
					issue, dep, providerName, sourceName, remediationsByDep
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
 * @param {Map<string, object>} remediationsByDep
 */
function processIssueRemediation(issue, dep, providerName, sourceName, remediationsByDep) {
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

	const priority = detectProviderPriority(fixedInPurl)
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
			severity,
			cves: cveId ? [cveId] : [],
			_priority: priority,
		})
		return
	}

	if (cveId && !existing.cves.includes(cveId)) {
		existing.cves.push(cveId)
	}

	mergeAdvisories(existing.advisories, advisories)

	if (priority > existing._priority) {
		existing.fixedInVersion = fixedInVersion
		existing.fixedInPurl = fixedInPurl
		existing.provider = providerName
		existing.source = sourceName
		existing.severity = higherSeverity(existing.severity, severity)
		existing._priority = priority
	} else if (priority === existing._priority) {
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
 * @param {object} providerReport
 * @param {string} providerName
 * @param {Map<string, object>} remediationsByDep
 */
function extractFromRecommendations(providerReport, providerName, remediationsByDep) {
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
		const priority = detectProviderPriority(recommendedPurl)
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
				_priority: priority,
			})
		} else if (priority > existing._priority) {
			existing.fixedInVersion = fixedInVersion
			existing.fixedInPurl = recommendedPurl
			existing.provider = providerName
			existing.source = 'recommendation'
			existing._priority = priority
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
 * Detects provider priority from PURL qualifiers.
 * @param {string} purlStr
 * @returns {number} priority level
 */
function detectProviderPriority(purlStr) {
	if (purlStr.includes('.rhlw-')) {
		return PROVIDER_PRIORITY.lightwell
	}
	if (purlStr.includes('.redhat-')) {
		return PROVIDER_PRIORITY.redhat
	}
	return PROVIDER_PRIORITY.generic
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
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
function compareVersions(a, b) {
	const partsA = a.split('.').map(s => parseInt(s, 10) || 0)
	const partsB = b.split('.').map(s => parseInt(s, 10) || 0)
	const len = Math.max(partsA.length, partsB.length)
	for (let i = 0; i < len; i++) {
		const diff = (partsA[i] || 0) - (partsB[i] || 0)
		if (diff !== 0) {
			return diff
		}
	}
	return 0
}

const SEVERITY_ORDER = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

/**
 * Returns the higher of two severity strings.
 * @param {string} a
 * @param {string} b
 * @returns {string}
 */
function higherSeverity(a, b) {
	const indexA = SEVERITY_ORDER.indexOf(a.toUpperCase())
	const indexB = SEVERITY_ORDER.indexOf(b.toUpperCase())
	return indexA >= indexB ? a : b
}
