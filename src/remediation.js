import { PackageURL } from 'packageurl-js'

/**
 * Extracts the major version segment from a version string.
 * @param {string} version
 * @returns {string} the first dot-separated segment
 */
function getMajorVersion(version) {
	return version.split('.')[0] || ''
}

/**
 * Version selection strategy that prefers the closest compatible version
 * within the same major version stream. Falls back to the lowest cross-major
 * version when no same-major option exists.
 * @type {{selectVersion: function(string[], string): string, resolveConflict: function(object, object): string}}
 */
export const closestCoverageStrategy = {
	selectVersion(fixedInVersions, currentVersion) {
		const currentMajor = getMajorVersion(currentVersion)
		const sameMajor = fixedInVersions.filter(v => getMajorVersion(v) === currentMajor)
		if (sameMajor.length > 0) {
			return sameMajor.sort((a, b) => compareVersions(b, a))[0]
		}
		return fixedInVersions.sort((a, b) => compareVersions(a, b))[0]
	},

	resolveConflict(existing, candidate) {
		if (existing._fromTrustedContent && !candidate._fromTrustedContent) {
			return 'existing'
		}
		if (!existing._fromTrustedContent && candidate._fromTrustedContent) {
			return 'candidate'
		}
		const currentMajor = getMajorVersion(existing.currentVersion)
		const existingSameMajor = getMajorVersion(existing.fixedInVersion) === currentMajor
		const candidateSameMajor = getMajorVersion(candidate.fixedInVersion) === currentMajor
		if (existingSameMajor && !candidateSameMajor) {
			return 'existing'
		}
		if (!existingSameMajor && candidateSameMajor) {
			return 'candidate'
		}
		return compareVersions(candidate.fixedInVersion, existing.fixedInVersion) > 0
			? 'candidate'
			: 'existing'
	},
}

/**
 * Version selection strategy that always picks the highest version regardless
 * of major version distance. Guarantees maximum CVE coverage but may produce
 * large version jumps. This is the original behavior before pluggable strategies.
 * @type {{selectVersion: function(string[], string): string, resolveConflict: function(object, object): string}}
 */
export const highestStrategy = {
	selectVersion(fixedInVersions) {
		return fixedInVersions.sort((a, b) => compareVersions(b, a))[0]
	},

	resolveConflict(existing, candidate) {
		if (existing._fromTrustedContent && !candidate._fromTrustedContent) {
			return 'existing'
		}
		if (!existing._fromTrustedContent && candidate._fromTrustedContent) {
			return 'candidate'
		}
		return compareVersions(candidate.fixedInVersion, existing.fixedInVersion) > 0
			? 'candidate'
			: 'existing'
	},
}

/**
 * Extracts actionable remediation instructions from a DA AnalysisReport response.
 *
 * Walks the provider/source/dependency/issue tree, collects fixedIn and trustedContent
 * remediation data, applies provider priority resolution, and uses the configured
 * version selection strategy to resolve conflicts. Dependencies with no remediation
 * data are skipped.
 *
 * @param {object} analysisReport - raw DA AnalysisReport JSON response
 * @param {object} [options] - extraction options
 * @param {string[]} [options.providerPriority] - provider names in descending priority order.
 *   The first entry has the highest priority. Providers not listed share the lowest priority.
 *   When omitted or empty, all providers are treated equally and the highest fix version wins.
 * @param {object} [options.versionStrategy] - version selection strategy with selectVersion
 *   and resolveConflict methods. Defaults to closestCoverageStrategy.
 * @returns {Array<{purl: string, groupId: string, artifactId: string, currentVersion: string, fixedInVersion: string, fixedInPurl: string, provider: string, source: string, advisories: Array<{id: string, url: string}>, severity: string, cves: string[]}>}
 */
export function extractRemediations(analysisReport, options = {}) {
	if (!analysisReport || !analysisReport.providers) {
		return []
	}

	const priorityMap = buildPriorityMap(options.providerPriority)
	const strategy = options.versionStrategy || closestCoverageStrategy
	const remediationsByDep = new Map()
	const rankByDep = new Map()

	for (const [providerName, providerReport] of Object.entries(analysisReport.providers)) {
		const providerRank = priorityMap.get(providerName) ?? 0
		extractFromSources(providerReport, providerName, providerRank, remediationsByDep, rankByDep, strategy)
		extractFromRecommendations(providerReport, providerName, providerRank, remediationsByDep, rankByDep)
	}

	return Array.from(remediationsByDep.values())
		.map((entry) => {
			delete entry._fromTrustedContent
			return entry
		})
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
 * @param {object} strategy - version selection strategy
 */
function extractFromSources(providerReport, providerName, providerRank, remediationsByDep, rankByDep, strategy) {
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
					issue, dep, providerName, sourceName, providerRank, remediationsByDep, rankByDep, strategy
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
 * @param {object} strategy - version selection strategy
 */
function processIssueRemediation(issue, dep, providerName, sourceName, providerRank, remediationsByDep, rankByDep, strategy) {
	const depPurl = dep.ref
	if (!depPurl) {
		return
	}

	let parsedDep
	try {
		parsedDep = PackageURL.fromString(depPurl)
	} catch {
		return
	}

	const currentVersion = parsedDep.version || ''
	const fixedInPurl = getFixedInPurl(issue, depPurl, strategy, currentVersion)
	if (!fixedInPurl) {
		return
	}

	const isTrustedContent = !!(issue.remediation && issue.remediation.trustedContent && issue.remediation.trustedContent.ref)

	let parsedFix
	try {
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
			currentVersion,
			fixedInVersion,
			fixedInPurl,
			provider: providerName,
			source: sourceName,
			advisories,
			severity: severity.toUpperCase(),
			cves: cveId ? [cveId] : [],
			_fromTrustedContent: isTrustedContent,
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
		existing._fromTrustedContent = isTrustedContent
		rankByDep.set(depPurl, providerRank)
	} else if (providerRank === existingRank) {
		const winner = strategy.resolveConflict(
			{ fixedInVersion: existing.fixedInVersion, _fromTrustedContent: existing._fromTrustedContent, currentVersion },
			{ fixedInVersion, _fromTrustedContent: isTrustedContent, currentVersion }
		)
		if (winner === 'candidate') {
			existing.fixedInVersion = fixedInVersion
			existing.fixedInPurl = fixedInPurl
			existing.provider = providerName
			existing.source = sourceName
			existing._fromTrustedContent = isTrustedContent
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
 * When fixedIn is an array of version strings (not PURLs), uses the strategy's
 * selectVersion to pick the best candidate and constructs a PURL from the dependency ref.
 * @param {object} issue
 * @param {string} depPurl - the dependency PURL, used to construct fixedIn PURLs from version strings
 * @param {object} strategy - version selection strategy
 * @param {string} currentVersion - the dependency's current version
 * @returns {string|undefined}
 */
function getFixedInPurl(issue, depPurl, strategy, currentVersion) {
	if (!issue.remediation) {
		return undefined
	}
	if (issue.remediation.trustedContent && issue.remediation.trustedContent.ref) {
		return issue.remediation.trustedContent.ref
	}
	const fixedIn = issue.remediation.fixedIn
	if (!fixedIn) {
		return undefined
	}
	if (typeof fixedIn === 'string') {
		return fixedIn
	}
	if (Array.isArray(fixedIn) && fixedIn.length > 0) {
		const version = fixedIn.length > 1
			? strategy.selectVersion(fixedIn, currentVersion)
			: fixedIn[0]
		if (typeof version === 'string' && version.startsWith('pkg:')) {
			return version
		}
		if (typeof version === 'string' && depPurl) {
			try {
				const parsed = PackageURL.fromString(depPurl)
				parsed.version = version
				return parsed.toString()
			} catch {
				return undefined
			}
		}
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
			if (diff !== 0) {return diff}
		} else {
			const cmp = segA.localeCompare(segB)
			if (cmp !== 0) {return cmp}
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
