import { expect } from 'chai'

import { extractRemediations, closestCoverageStrategy, highestStrategy } from '../src/remediation.js'

/**
 * Builds a minimal AnalysisReport with a single provider, source, dependency, and issue.
 * @param {object} overrides - optional overrides for the fixture structure
 * @returns {object}
 */
function buildReport(overrides = {}) {
	const {
		providerName = 'provider-a',
		sourceName = 'source-a',
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
		/** Verifies that remediations from a single provider are correctly extracted. */
		test('extracts remediations from a single provider', () => {
			// Given a report with one provider
			const report = buildReport({
				trustedContentRef: 'pkg:maven/org.apache.commons/commons-text@1.10.0?type=jar',
				fixedIn: null,
				advisory: { id: 'ADV-2022-001', url: 'https://example.com/ADV-2022-001' },
			})

			// When extracting remediations
			const result = extractRemediations(report)

			// Then the result should contain one remediation entry
			expect(result).to.have.lengthOf(1)
			expect(result[0].provider).to.equal('provider-a')
			expect(result[0].fixedInVersion).to.equal('1.10.0')
			expect(result[0].groupId).to.equal('org.apache.commons')
			expect(result[0].artifactId).to.equal('commons-text')
			expect(result[0].currentVersion).to.equal('1.9')
			expect(result[0].cves).to.deep.equal(['CVE-2022-42889'])
			expect(result[0].advisories).to.deep.equal([
				{ id: 'ADV-2022-001', url: 'https://example.com/ADV-2022-001' },
			])
		})

		/** Verifies that the higher-priority provider wins when both provide a fix for the same dep. */
		test('higher-priority provider wins for the same dependency', () => {
			// Given a report with two providers for the same dependency
			const report = buildReport({
				providerName: 'provider-low',
				fixedIn: 'pkg:maven/org.apache.commons/commons-text@1.10.0?type=jar',
				extraProviders: {
					'provider-high': {
						sources: {
							'source-high': {
								dependencies: [{
									ref: 'pkg:maven/org.apache.commons/commons-text@1.9',
									issues: [{
										id: 'CVE-2022-42889',
										severity: 'CRITICAL',
										remediation: {
											trustedContent: {
												ref: 'pkg:maven/org.apache.commons/commons-text@1.10.1?type=jar',
											},
										},
									}],
								}],
							},
						},
					},
				},
			})

			// When extracting with provider-high having higher priority
			const result = extractRemediations(report, {
				providerPriority: ['provider-high', 'provider-low'],
			})

			// Then provider-high should win
			expect(result).to.have.lengthOf(1)
			expect(result[0].provider).to.equal('provider-high')
			expect(result[0].fixedInVersion).to.equal('1.10.1')
		})

		/** Verifies that the second-priority provider wins over unlisted providers. */
		test('listed provider takes precedence over unlisted provider', () => {
			// Given a report with a listed and an unlisted provider
			const report = buildReport({
				providerName: 'unlisted-provider',
				fixedIn: 'pkg:maven/org.apache.commons/commons-text@1.10.0?type=jar',
				extraProviders: {
					'listed-provider': {
						sources: {
							'source-listed': {
								dependencies: [{
									ref: 'pkg:maven/org.apache.commons/commons-text@1.9',
									issues: [{
										id: 'CVE-2022-42889',
										severity: 'CRITICAL',
										remediation: {
											fixedIn: 'pkg:maven/org.apache.commons/commons-text@1.9.1?type=jar',
										},
									}],
								}],
							},
						},
					},
				},
			})

			// When extracting with only listed-provider in the priority list
			const result = extractRemediations(report, {
				providerPriority: ['listed-provider'],
			})

			// Then the listed provider should win even though its version is lower
			expect(result).to.have.lengthOf(1)
			expect(result[0].provider).to.equal('listed-provider')
			expect(result[0].fixedInVersion).to.equal('1.9.1')
		})

		/** Verifies that without providerPriority, the highest version wins. */
		test('without providerPriority, highest version wins across providers', () => {
			// Given two providers with different fix versions and no priority config
			const report = buildReport({
				providerName: 'provider-a',
				fixedIn: 'pkg:maven/org.apache.commons/commons-text@1.10.0',
				extraProviders: {
					'provider-b': {
						sources: {
							'source-b': {
								dependencies: [{
									ref: 'pkg:maven/org.apache.commons/commons-text@1.9',
									issues: [{
										id: 'CVE-2022-42889',
										severity: 'CRITICAL',
										remediation: {
											fixedIn: 'pkg:maven/org.apache.commons/commons-text@1.11.0',
										},
									}],
								}],
							},
						},
					},
				},
			})

			// When extracting without providerPriority
			const result = extractRemediations(report)

			// Then the highest version should win
			expect(result).to.have.lengthOf(1)
			expect(result[0].fixedInVersion).to.equal('1.11.0')
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

		/** Verifies that severity values are normalized to uppercase in output. */
		test('severity is normalized to uppercase', () => {
			const report = buildReport({
				severity: 'critical',
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
					'provider-a': {
						sources: {
							'source-a': {
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
					'provider-a': {
						sources: {
							'source-a': {
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
			const opts = { providerPriority: ['provider-a'] }

			const result1 = extractRemediations(report, opts)
			const result2 = extractRemediations(report, opts)

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

		/** Verifies that a source-based remediation takes precedence over a recommendation when the provider has higher priority. */
		test('source remediation takes precedence over recommendation when higher priority', () => {
			// Given a report where source has a fix and recommendation also exists
			const report = buildReport({
				depRef: 'pkg:maven/com.example/lib@1.0.0',
				fixedIn: 'pkg:maven/com.example/lib@1.1.0',
				recommendations: {
					dependencies: [{
						ref: 'pkg:maven/com.example/lib@1.0.0',
						recommendation: {
							ref: 'pkg:maven/com.example/lib@1.2.0',
						},
					}],
				},
			})

			const result = extractRemediations(report)

			// Source remediation is processed first; recommendation from same provider/rank
			// takes the higher version
			expect(result).to.have.lengthOf(1)
			expect(result[0].fixedInVersion).to.equal('1.2.0')
		})
	})

	suite('source and recommendation merging', () => {
		/** Verifies that CVEs from source issues are preserved when a recommendation also exists for the same dep. */
		test('source CVEs are preserved when recommendation provides a higher version', () => {
			// Given a dep with a CVE from source and a recommendation with a higher version
			const report = buildReport({
				depRef: 'pkg:maven/com.example/lib@1.0.0',
				issueId: 'CVE-2024-11111',
				severity: 'HIGH',
				trustedContentRef: 'pkg:maven/com.example/lib@1.1.0',
				fixedIn: null,
				advisory: { id: 'ADV-001', url: 'https://example.com/ADV-001' },
				recommendations: {
					dependencies: [{
						ref: 'pkg:maven/com.example/lib@1.0.0',
						recommendation: {
							ref: 'pkg:maven/com.example/lib@1.2.0',
						},
					}],
				},
			})

			const result = extractRemediations(report)

			// Then the entry should have the recommendation's higher version but retain source CVEs
			expect(result).to.have.lengthOf(1)
			expect(result[0].fixedInVersion).to.equal('1.2.0')
			expect(result[0].cves).to.deep.equal(['CVE-2024-11111'])
			expect(result[0].advisories).to.deep.equal([
				{ id: 'ADV-001', url: 'https://example.com/ADV-001' },
			])
		})
	})

	suite('output structure', () => {
		/** Verifies that the output includes all required fields with correct types. */
		test('output includes all required fields', () => {
			const report = buildReport({
				trustedContentRef: 'pkg:maven/org.apache.commons/commons-text@1.10.0?type=jar',
				fixedIn: null,
				advisory: { id: 'ADV-2022-001', url: 'https://example.com/advisory' },
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

suite('version selection strategies', () => {
	suite('closestCoverageStrategy.selectVersion', () => {
		/** Verifies that same-major version is preferred when available. */
		test('picks same-major version when available', () => {
			const result = closestCoverageStrategy.selectVersion(
				['2.13.9.Final-redhat-00003', '3.2.9.Final-redhat-00003'],
				'2.13.5.Final'
			)
			expect(result).to.equal('2.13.9.Final-redhat-00003')
		})

		/** Verifies highest same-major is picked when multiple same-major options exist. */
		test('picks highest same-major when multiple exist', () => {
			const result = closestCoverageStrategy.selectVersion(
				['2.13.7.Final', '2.13.9.Final', '3.0.0'],
				'2.13.5.Final'
			)
			expect(result).to.equal('2.13.9.Final')
		})

		/** Verifies fallback to lowest cross-major when no same-major exists. */
		test('falls back to lowest cross-major when no same-major exists', () => {
			const result = closestCoverageStrategy.selectVersion(
				['3.8.6.1', '4.0.0'],
				'2.13.5.Final'
			)
			expect(result).to.equal('3.8.6.1')
		})

		/** Verifies single-element array returns that element. */
		test('returns only option when array has one element', () => {
			const result = closestCoverageStrategy.selectVersion(['3.8.6.1'], '2.13.5.Final')
			expect(result).to.equal('3.8.6.1')
		})
	})

	suite('closestCoverageStrategy.resolveConflict', () => {
		/** Verifies trustedContent wins over non-trustedContent. */
		test('trustedContent wins over non-trustedContent', () => {
			const result = closestCoverageStrategy.resolveConflict(
				{ fixedInVersion: '2.17.1.redhat-00002', _fromTrustedContent: true, currentVersion: '2.17.1' },
				{ fixedInVersion: '3.0.0', _fromTrustedContent: false, currentVersion: '2.17.1' }
			)
			expect(result).to.equal('existing')
		})

		/** Verifies non-trustedContent loses to trustedContent candidate. */
		test('trustedContent candidate wins over non-trustedContent existing', () => {
			const result = closestCoverageStrategy.resolveConflict(
				{ fixedInVersion: '3.0.0', _fromTrustedContent: false, currentVersion: '2.17.1' },
				{ fixedInVersion: '2.17.1.redhat-00002', _fromTrustedContent: true, currentVersion: '2.17.1' }
			)
			expect(result).to.equal('candidate')
		})

		/** Verifies same-major wins over cross-major. */
		test('same-major wins over cross-major', () => {
			const result = closestCoverageStrategy.resolveConflict(
				{ fixedInVersion: '2.13.9.Final', _fromTrustedContent: false, currentVersion: '2.13.5.Final' },
				{ fixedInVersion: '3.8.6.1', _fromTrustedContent: false, currentVersion: '2.13.5.Final' }
			)
			expect(result).to.equal('existing')
		})

		/** Verifies cross-major candidate loses to same-major existing. */
		test('cross-major candidate loses to same-major existing', () => {
			const result = closestCoverageStrategy.resolveConflict(
				{ fixedInVersion: '3.8.6.1', _fromTrustedContent: false, currentVersion: '2.13.5.Final' },
				{ fixedInVersion: '2.13.9.Final', _fromTrustedContent: false, currentVersion: '2.13.5.Final' }
			)
			expect(result).to.equal('candidate')
		})

		/** Verifies higher version wins when both are same-major. */
		test('higher version wins when both same-major', () => {
			const result = closestCoverageStrategy.resolveConflict(
				{ fixedInVersion: '2.13.7.Final', _fromTrustedContent: false, currentVersion: '2.13.5.Final' },
				{ fixedInVersion: '2.13.9.Final', _fromTrustedContent: false, currentVersion: '2.13.5.Final' }
			)
			expect(result).to.equal('candidate')
		})
	})

	suite('highestStrategy.selectVersion', () => {
		/** Verifies highest version is selected regardless of major. */
		test('picks highest version regardless of major', () => {
			const result = highestStrategy.selectVersion(
				['2.13.9.Final-redhat-00003', '3.2.9.Final-redhat-00003'],
				'2.13.5.Final'
			)
			expect(result).to.equal('3.2.9.Final-redhat-00003')
		})
	})

	suite('highestStrategy.resolveConflict', () => {
		/** Verifies higher version wins. */
		test('higher version wins', () => {
			const result = highestStrategy.resolveConflict(
				{ fixedInVersion: '2.13.9.Final', _fromTrustedContent: false, currentVersion: '2.13.5.Final' },
				{ fixedInVersion: '3.8.6.1', _fromTrustedContent: false, currentVersion: '2.13.5.Final' }
			)
			expect(result).to.equal('candidate')
		})

		/** Verifies trustedContent still wins over higher version. */
		test('trustedContent wins over higher version', () => {
			const result = highestStrategy.resolveConflict(
				{ fixedInVersion: '2.17.1.redhat-00002', _fromTrustedContent: true, currentVersion: '2.17.1' },
				{ fixedInVersion: '3.0.0', _fromTrustedContent: false, currentVersion: '2.17.1' }
			)
			expect(result).to.equal('existing')
		})
	})

	suite('extractRemediations with strategies', () => {
		/** Verifies default strategy is closestCoverageStrategy — picks same-major over cross-major. */
		test('default strategy picks same-major version for quarkus-resteasy scenario', () => {
			// Given a dependency with CVEs having fixes in 2.x and 3.x
			const report = {
				providers: {
					rhtpa: {
						sources: {
							'osv-github': {
								dependencies: [{
									ref: 'pkg:maven/io.quarkus/quarkus-resteasy@2.13.5.Final',
									issues: [
										{
											id: 'CVE-2025-1634',
											severity: 'HIGH',
											remediation: { fixedIn: ['3.8.6.1'] },
										},
										{
											id: 'CVE-2023-6267',
											severity: 'HIGH',
											remediation: { fixedIn: ['2.13.9.Final-redhat-00003', '3.2.9.Final-redhat-00003'] },
										},
										{
											id: 'CVE-2023-5675',
											severity: 'HIGH',
											remediation: { fixedIn: ['2.13.9.Final-redhat-00003', '3.2.9.Final-redhat-00003'] },
										},
									],
								}],
							},
						},
					},
				},
			}

			// When extracting with default strategy
			const result = extractRemediations(report)

			// Then same-major version should be preferred
			expect(result).to.have.lengthOf(1)
			expect(result[0].fixedInVersion).to.equal('2.13.9.Final-redhat-00003')
			expect(result[0].cves).to.include('CVE-2025-1634')
			expect(result[0].cves).to.include('CVE-2023-6267')
			expect(result[0].cves).to.include('CVE-2023-5675')
		})

		/** Verifies highestStrategy picks highest version across all CVEs. */
		test('highestStrategy picks highest version for same scenario', () => {
			const report = {
				providers: {
					rhtpa: {
						sources: {
							'osv-github': {
								dependencies: [{
									ref: 'pkg:maven/io.quarkus/quarkus-resteasy@2.13.5.Final',
									issues: [
										{
											id: 'CVE-2025-1634',
											severity: 'HIGH',
											remediation: { fixedIn: ['3.8.6.1'] },
										},
										{
											id: 'CVE-2023-6267',
											severity: 'HIGH',
											remediation: { fixedIn: ['2.13.9.Final-redhat-00003', '3.2.9.Final-redhat-00003'] },
										},
									],
								}],
							},
						},
					},
				},
			}

			const result = extractRemediations(report, { versionStrategy: highestStrategy })

			expect(result).to.have.lengthOf(1)
			expect(result[0].fixedInVersion).to.equal('3.8.6.1')
		})

		/** Verifies default strategy is closestCoverageStrategy. */
		test('default strategy is closestCoverageStrategy', () => {
			const report = {
				providers: {
					rhtpa: {
						sources: {
							'osv-github': {
								dependencies: [{
									ref: 'pkg:maven/com.example/lib@1.0.0',
									issues: [{
										id: 'CVE-2024-00001',
										severity: 'HIGH',
										remediation: { fixedIn: ['1.0.1', '2.0.0'] },
									}],
								}],
							},
						},
					},
				},
			}

			const result = extractRemediations(report)

			expect(result).to.have.lengthOf(1)
			expect(result[0].fixedInVersion).to.equal('1.0.1')
		})
	})
})
