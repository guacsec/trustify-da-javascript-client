import { expect } from 'chai'

import { extractRemediations } from '../src/remediation.js'

/**
 * Builds a minimal AnalysisReport with a single provider, source, dependency, and issue.
 * @param {object} overrides - optional overrides for the fixture structure
 * @returns {object}
 */
function buildReport(overrides = {}) {
	const {
		providerName = 'redhat',
		sourceName = 'redhat-security',
		depRef = 'pkg:maven/org.apache.commons/commons-text@1.9',
		issueId = 'CVE-2022-42889',
		severity = 'CRITICAL',
		fixedIn = 'pkg:maven/org.apache.commons/commons-text@1.10.0',
		trustedContentRef = undefined,
		advisory = undefined,
		recommendations = undefined,
		extraIssues = [],
		extraDeps = [],
		extraProviders = {},
	} = overrides

	const remediation = {}
	if (fixedIn) {
		remediation.fixedIn = fixedIn
	}
	if (trustedContentRef) {
		remediation.trustedContent = { ref: trustedContentRef }
		if (advisory) {
			remediation.trustedContent.advisory = advisory
		}
	}

	const issue = {
		id: issueId,
		severity,
		remediation: Object.keys(remediation).length > 0 ? remediation : undefined,
	}

	const dep = {
		ref: depRef,
		issues: [issue, ...extraIssues],
	}

	const sourceReport = {
		dependencies: [dep, ...extraDeps],
	}

	const providerReport = {
		sources: { [sourceName]: sourceReport },
	}
	if (recommendations) {
		providerReport.recommendations = recommendations
	}

	return {
		providers: {
			[providerName]: providerReport,
			...extraProviders,
		},
	}
}

suite('remediation extractor', () => {
	suite('provider priority resolution', () => {
		/** Verifies that Lightwell (.rhlw-) remediations are correctly extracted. */
		test('extracts Lightwell remediations from trustedContent', () => {
			// Given a report with a Lightwell trusted content remediation
			const report = buildReport({
				providerName: 'lightwell',
				sourceName: 'lightwell-security',
				trustedContentRef: 'pkg:maven/org.apache.commons/commons-text@1.10.0.rhlw-00001?type=jar',
				fixedIn: null,
				advisory: { id: 'RHLW-2022-001', url: 'https://lightwell.example.com/RHLW-2022-001' },
			})

			// When extracting remediations
			const result = extractRemediations(report)

			// Then the result should contain one Lightwell remediation
			expect(result).to.have.lengthOf(1)
			expect(result[0].provider).to.equal('lightwell')
			expect(result[0].fixedInVersion).to.equal('1.10.0.rhlw-00001')
			expect(result[0].fixedInPurl).to.include('.rhlw-')
			expect(result[0].groupId).to.equal('org.apache.commons')
			expect(result[0].artifactId).to.equal('commons-text')
			expect(result[0].currentVersion).to.equal('1.9')
			expect(result[0].cves).to.deep.equal(['CVE-2022-42889'])
			expect(result[0].advisories).to.deep.equal([
				{ id: 'RHLW-2022-001', url: 'https://lightwell.example.com/RHLW-2022-001' },
			])
		})

		/** Verifies that Red Hat VENDOR_FIX remediations are correctly extracted. */
		test('extracts Red Hat remediations from fixedIn', () => {
			// Given a report with a Red Hat fixedIn PURL
			const report = buildReport({
				fixedIn: 'pkg:maven/org.apache.commons/commons-text@1.10.0.redhat-00001?type=jar',
				advisory: undefined,
			})

			// When extracting remediations
			const result = extractRemediations(report)

			// Then the result should contain one Red Hat remediation
			expect(result).to.have.lengthOf(1)
			expect(result[0].provider).to.equal('redhat')
			expect(result[0].fixedInVersion).to.equal('1.10.0.redhat-00001')
			expect(result[0].cves).to.deep.equal(['CVE-2022-42889'])
		})

		/** Verifies that Lightwell takes precedence over Red Hat for the same dependency. */
		test('Lightwell remediations take precedence over Red Hat', () => {
			// Given a report with both Lightwell and Red Hat providers for the same dependency
			const report = buildReport({
				providerName: 'redhat',
				fixedIn: 'pkg:maven/org.apache.commons/commons-text@1.10.0.redhat-00001?type=jar',
				extraProviders: {
					lightwell: {
						sources: {
							'lightwell-security': {
								dependencies: [{
									ref: 'pkg:maven/org.apache.commons/commons-text@1.9',
									issues: [{
										id: 'CVE-2022-42889',
										severity: 'CRITICAL',
										remediation: {
											trustedContent: {
												ref: 'pkg:maven/org.apache.commons/commons-text@1.10.0.rhlw-00001?type=jar',
											},
										},
									}],
								}],
							},
						},
					},
				},
			})

			// When extracting remediations
			const result = extractRemediations(report)

			// Then Lightwell should win
			expect(result).to.have.lengthOf(1)
			expect(result[0].fixedInPurl).to.include('.rhlw-')
			expect(result[0].provider).to.equal('lightwell')
		})

		/** Verifies that Red Hat takes precedence over generic remediations. */
		test('Red Hat remediations take precedence over generic', () => {
			// Given a report with both generic and Red Hat providers
			const report = buildReport({
				providerName: 'generic-provider',
				fixedIn: 'pkg:maven/org.apache.commons/commons-text@1.10.0?type=jar',
				extraProviders: {
					redhat: {
						sources: {
							'redhat-security': {
								dependencies: [{
									ref: 'pkg:maven/org.apache.commons/commons-text@1.9',
									issues: [{
										id: 'CVE-2022-42889',
										severity: 'CRITICAL',
										remediation: {
											fixedIn: 'pkg:maven/org.apache.commons/commons-text@1.10.0.redhat-00001?type=jar',
										},
									}],
								}],
							},
						},
					},
				},
			})

			// When extracting remediations
			const result = extractRemediations(report)

			// Then Red Hat should win
			expect(result).to.have.lengthOf(1)
			expect(result[0].fixedInPurl).to.include('.redhat-')
			expect(result[0].provider).to.equal('redhat')
		})
	})

	suite('version merging', () => {
		/** Verifies that multiple CVEs on the same dependency produce a single entry with the highest fix version. */
		test('multiple CVEs on same dependency produce single entry with highest version', () => {
			// Given a dependency with two CVEs having different fix versions from the same provider
			const report = buildReport({
				fixedIn: 'pkg:maven/org.apache.commons/commons-text@1.10.0',
				extraIssues: [{
					id: 'CVE-2023-99999',
					severity: 'HIGH',
					remediation: {
						fixedIn: 'pkg:maven/org.apache.commons/commons-text@1.11.0',
					},
				}],
			})

			// When extracting remediations
			const result = extractRemediations(report)

			// Then a single entry should be returned with the highest version
			expect(result).to.have.lengthOf(1)
			expect(result[0].fixedInVersion).to.equal('1.11.0')
			expect(result[0].cves).to.include('CVE-2022-42889')
			expect(result[0].cves).to.include('CVE-2023-99999')
			expect(result[0].cves).to.have.lengthOf(2)
		})

		/** Verifies that the highest severity is preserved across merged CVEs. */
		test('highest severity is preserved across merged CVEs', () => {
			// Given two CVEs with different severities
			const report = buildReport({
				severity: 'MEDIUM',
				fixedIn: 'pkg:maven/org.apache.commons/commons-text@1.10.0',
				extraIssues: [{
					id: 'CVE-2023-99999',
					severity: 'CRITICAL',
					remediation: {
						fixedIn: 'pkg:maven/org.apache.commons/commons-text@1.10.0',
					},
				}],
			})

			const result = extractRemediations(report)

			expect(result).to.have.lengthOf(1)
			expect(result[0].severity).to.equal('CRITICAL')
		})
	})

	suite('edge cases', () => {
		/** Verifies that dependencies with no remediation data produce an empty result. */
		test('dependencies with no remediation data return empty result', () => {
			const report = {
				providers: {
					redhat: {
						sources: {
							'redhat-security': {
								dependencies: [{
									ref: 'pkg:maven/org.apache.commons/commons-text@1.9',
									issues: [{
										id: 'CVE-2022-42889',
										severity: 'CRITICAL',
									}],
								}],
							},
						},
					},
				},
			}

			const result = extractRemediations(report)

			expect(result).to.deep.equal([])
		})

		/** Verifies that null/undefined input returns empty array. */
		test('null input returns empty array', () => {
			expect(extractRemediations(null)).to.deep.equal([])
			expect(extractRemediations(undefined)).to.deep.equal([])
		})

		/** Verifies that a report with no providers returns empty array. */
		test('report with empty providers returns empty array', () => {
			expect(extractRemediations({ providers: {} })).to.deep.equal([])
		})

		/** Verifies that issues with no fixedIn or trustedContent ref are skipped. */
		test('issues with empty remediation object are skipped', () => {
			const report = {
				providers: {
					redhat: {
						sources: {
							'redhat-security': {
								dependencies: [{
									ref: 'pkg:maven/org.example/lib@1.0',
									issues: [{
										id: 'CVE-2024-00001',
										severity: 'LOW',
										remediation: {},
									}],
								}],
							},
						},
					},
				},
			}

			const result = extractRemediations(report)

			expect(result).to.deep.equal([])
		})

		/** Verifies that the same input always produces the same output (idempotent). */
		test('same input always produces same output', () => {
			const report = buildReport()

			const result1 = extractRemediations(report)
			const result2 = extractRemediations(report)

			expect(result1).to.deep.equal(result2)
		})
	})

	suite('recommendations', () => {
		/** Verifies that package replacement recommendations are extracted. */
		test('extracts recommendation data as remediation', () => {
			// Given a report with a recommendation section
			const report = buildReport({
				fixedIn: null,
				issueId: 'CVE-2024-00001',
				recommendations: {
					dependencies: [{
						ref: 'pkg:maven/com.example/old-lib@1.0.0',
						recommendation: {
							ref: 'pkg:maven/com.example/new-lib@2.0.0',
						},
					}],
				},
			})

			// When extracting remediations
			const result = extractRemediations(report)

			// Then the recommendation should appear as a remediation entry
			const rec = result.find(r => r.purl === 'pkg:maven/com.example/old-lib@1.0.0')
			expect(rec).to.not.be.undefined
			expect(rec.fixedInVersion).to.equal('2.0.0')
			expect(rec.fixedInPurl).to.equal('pkg:maven/com.example/new-lib@2.0.0')
			expect(rec.source).to.equal('recommendation')
		})

		/** Verifies that a source-based remediation takes precedence over a recommendation for the same dep. */
		test('source remediation takes precedence over recommendation when higher priority', () => {
			// Given a report with both a source remediation and a recommendation for different deps
			const report = buildReport({
				depRef: 'pkg:maven/com.example/lib@1.0.0',
				fixedIn: 'pkg:maven/com.example/lib@1.1.0.redhat-00001',
				recommendations: {
					dependencies: [{
						ref: 'pkg:maven/com.example/lib@1.0.0',
						recommendation: {
							ref: 'pkg:maven/com.example/lib@1.1.0',
						},
					}],
				},
			})

			const result = extractRemediations(report)

			expect(result).to.have.lengthOf(1)
			expect(result[0].fixedInPurl).to.include('.redhat-')
		})
	})

	suite('output structure', () => {
		/** Verifies that the output includes all required fields with correct types. */
		test('output includes all required fields', () => {
			const report = buildReport({
				trustedContentRef: 'pkg:maven/org.apache.commons/commons-text@1.10.0.rhlw-00001?type=jar',
				fixedIn: null,
				advisory: { id: 'RHLW-2022-001', url: 'https://example.com/advisory' },
			})

			const result = extractRemediations(report)

			expect(result).to.have.lengthOf(1)
			const entry = result[0]
			expect(entry).to.have.property('purl').that.is.a('string')
			expect(entry).to.have.property('groupId').that.is.a('string')
			expect(entry).to.have.property('artifactId').that.is.a('string')
			expect(entry).to.have.property('currentVersion').that.is.a('string')
			expect(entry).to.have.property('fixedInVersion').that.is.a('string')
			expect(entry).to.have.property('fixedInPurl').that.is.a('string')
			expect(entry).to.have.property('provider').that.is.a('string')
			expect(entry).to.have.property('source').that.is.a('string')
			expect(entry).to.have.property('advisories').that.is.an('array')
			expect(entry).to.have.property('severity').that.is.a('string')
			expect(entry).to.have.property('cves').that.is.an('array')
			expect(entry).to.not.have.property('_priority')
		})
	})
})
