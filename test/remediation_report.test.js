import { expect } from 'chai'

import { generateReport, generateDeduplicationKey } from '../src/remediation_report.js'

/**
 * Builds a remediation entry matching the shape returned by extractRemediations.
 * @param {object} [overrides]
 * @returns {object}
 */
function buildRemediation(overrides = {}) {
	return {
		purl: 'pkg:maven/org.apache.commons/commons-text@1.9',
		groupId: 'org.apache.commons',
		artifactId: 'commons-text',
		currentVersion: '1.9',
		fixedInVersion: '1.10.0',
		fixedInPurl: 'pkg:maven/org.apache.commons/commons-text@1.10.0',
		provider: 'trusted-content',
		source: 'redhat',
		vulnerabilities: [{
			id: 'CVE-2022-42889',
			severity: 'CRITICAL',
			advisories: [{ id: 'RHSA-2022:001', url: 'https://access.redhat.com/errata/RHSA-2022:001' }],
		}],
		...overrides,
	}
}

suite('remediation report generator', () => {
	suite('per-dependency report', () => {
		/** Verifies that per-dependency report includes CVE IDs, severity, and advisory links. */
		test('includes CVE IDs, severity, and advisory links for a single remediation', () => {
			// Given a single remediation entry
			const remediations = [buildRemediation()]

			// When generating a per-dependency report
			const report = generateReport(remediations)

			// Then the report should contain the dependency update header
			expect(report).to.include(
				'## Security Update: org.apache.commons:commons-text 1.9 → 1.10.0'
			)
			expect(report).to.include('**Provider:** trusted-content | **Source:** redhat')
			expect(report).to.include('CVE-2022-42889')
			expect(report).to.include('CRITICAL')
			expect(report).to.include(
				'[RHSA-2022:001](https://access.redhat.com/errata/RHSA-2022:001)'
			)
		})

		/** Verifies that multiple CVEs for the same dependency each get a row. */
		test('renders one row per CVE in the vulnerability table', () => {
			// Given a remediation entry with two CVEs
			const remediations = [buildRemediation({
				vulnerabilities: [
					{ id: 'CVE-2022-42889', severity: 'CRITICAL', advisories: [] },
					{ id: 'CVE-2023-99999', severity: 'HIGH', advisories: [] },
				],
			})]

			// When generating the report
			const report = generateReport(remediations)

			// Then each CVE should appear as a table row
			expect(report).to.include('| CVE-2022-42889 |')
			expect(report).to.include('| CVE-2023-99999 |')
		})

		/** Verifies that multiple remediations produce separate sections. */
		test('produces separate sections for multiple remediations', () => {
			// Given two different remediation entries
			const remediations = [
				buildRemediation(),
				buildRemediation({
					purl: 'pkg:maven/com.example/lib@1.0.0',
					groupId: 'com.example',
					artifactId: 'lib',
					currentVersion: '1.0.0',
					fixedInVersion: '2.0.0',
					provider: 'snyk',
					source: 'snyk-db',
					vulnerabilities: [{ id: 'CVE-2024-00001', severity: 'HIGH', advisories: [] }],
				}),
			]

			// When generating the report
			const report = generateReport(remediations)

			// Then both dependency sections should appear
			expect(report).to.include(
				'## Security Update: org.apache.commons:commons-text 1.9 → 1.10.0'
			)
			expect(report).to.include(
				'## Security Update: com.example:lib 1.0.0 → 2.0.0'
			)
		})

		/** Verifies that provider source is attributed in every entry. */
		test('attributes provider source in every entry', () => {
			const remediations = [
				buildRemediation({ provider: 'trusted-content', source: 'redhat' }),
				buildRemediation({
					purl: 'pkg:npm/lodash@4.17.20',
					groupId: '',
					artifactId: 'lodash',
					currentVersion: '4.17.20',
					fixedInVersion: '4.17.21',
					provider: 'snyk',
					source: 'snyk-db',
					vulnerabilities: [{ id: 'CVE-2021-23337', severity: 'HIGH', advisories: [] }],
				}),
			]

			const report = generateReport(remediations)

			expect(report).to.include('**Provider:** trusted-content | **Source:** redhat')
			expect(report).to.include('**Provider:** snyk | **Source:** snyk-db')
		})

		/** Verifies that a dependency with no groupId uses only artifactId. */
		test('handles dependencies without groupId', () => {
			const remediations = [buildRemediation({
				groupId: '',
				artifactId: 'lodash',
			})]

			const report = generateReport(remediations)

			expect(report).to.include('## Security Update: lodash 1.9 → 1.10.0')
		})

		/** Verifies that advisories without URLs are rendered as plain text. */
		test('renders advisories without URLs as plain text', () => {
			const remediations = [buildRemediation({
				vulnerabilities: [{
					id: 'CVE-2022-42889',
					severity: 'CRITICAL',
					advisories: [{ id: 'ADV-001', url: '' }],
				}],
			})]

			const report = generateReport(remediations)

			expect(report).to.include('ADV-001')
			expect(report).to.not.include('[ADV-001]()')
		})

		/** Verifies that entries with no advisories show a dash placeholder. */
		test('shows dash for entries with no advisories', () => {
			const remediations = [buildRemediation({
				vulnerabilities: [{ id: 'CVE-2022-42889', severity: 'CRITICAL', advisories: [] }],
			})]

			const report = generateReport(remediations)

			expect(report).to.include('| - |')
		})

		/** Verifies that each CVE row renders its OWN severity and advisories from vulnerabilities. */
		test('renders per-CVE severity and advisories from vulnerabilities', () => {
			// Given a remediation whose CVEs have distinct severities and advisories
			const remediations = [buildRemediation({
				vulnerabilities: [
					{
						id: 'CVE-2025-41242',
						severity: 'MEDIUM',
						advisories: [{ id: 'GHSA-mod', url: 'https://example.com/mod' }],
					},
					{
						id: 'CVE-2024-99999',
						severity: 'CRITICAL',
						advisories: [{ id: 'GHSA-crit', url: 'https://example.com/crit' }],
					},
				],
			})]

			// When generating the per-dependency report
			const report = generateReport(remediations)

			// Then each row shows its own severity + advisory, not the dep-level max
			expect(report).to.include(
				'| CVE-2025-41242 | MEDIUM | [GHSA-mod](https://example.com/mod) |'
			)
			expect(report).to.include(
				'| CVE-2024-99999 | CRITICAL | [GHSA-crit](https://example.com/crit) |'
			)
			// The moderate CVE must NOT be inflated to CRITICAL
			expect(report).to.not.include('| CVE-2025-41242 | CRITICAL |')
		})

		/** Verifies the update heading renders the fix version. */
		test('renders the fix version in the update heading', () => {
			const remediations = [buildRemediation({ fixedInVersion: '1.10.0' })]

			const report = generateReport(remediations)

			expect(report).to.include('1.9 → 1.10.0')
		})
	})

	suite('bundled report', () => {
		/** Verifies that bundled report groups remediations by severity. */
		test('groups all remediations by severity in a single document', () => {
			// Given remediations with different severities
			const remediations = [
				buildRemediation(),
				buildRemediation({
					purl: 'pkg:maven/com.example/lib@1.0.0',
					groupId: 'com.example',
					artifactId: 'lib',
					currentVersion: '1.0.0',
					fixedInVersion: '2.0.0',
					provider: 'snyk',
					source: 'snyk-db',
					vulnerabilities: [{ id: 'CVE-2024-00001', severity: 'HIGH', advisories: [] }],
				}),
			]

			// When generating a bundled report
			const report = generateReport(remediations, { groupBy: 'bundle' })

			// Then the report should have a summary header and severity sections
			expect(report).to.include('# Security Update Summary')
			expect(report).to.include('## CRITICAL')
			expect(report).to.include('## HIGH')
			// CRITICAL should appear before HIGH (descending severity order)
			expect(report.indexOf('## CRITICAL')).to.be.lessThan(
				report.indexOf('## HIGH')
			)
		})

		/** Verifies that the bundled report table includes all expected columns. */
		test('includes dependency, version, provider, CVEs, and advisory columns', () => {
			const remediations = [buildRemediation()]

			const report = generateReport(remediations, { groupBy: 'bundle' })

			expect(report).to.include(
				'| Dependency | Current | Fixed | Provider | CVEs | Advisory |'
			)
			expect(report).to.include('org.apache.commons:commons-text')
			expect(report).to.include('1.9')
			expect(report).to.include('1.10.0')
			expect(report).to.include('trusted-content')
			expect(report).to.include('CVE-2022-42889')
		})

		/** Verifies that empty severity groups are omitted. */
		test('omits severity groups with no entries', () => {
			const remediations = [buildRemediation({
				vulnerabilities: [{ id: 'CVE-2022-42889', severity: 'HIGH', advisories: [] }],
			})]

			const report = generateReport(remediations, { groupBy: 'bundle' })

			expect(report).to.include('## HIGH')
			expect(report).to.not.include('## CRITICAL')
			expect(report).to.not.include('## MEDIUM')
			expect(report).to.not.include('## LOW')
			expect(report).to.not.include('## UNKNOWN')
		})
	})

	suite('dry-run report', () => {
		/** Verifies that dry-run output shows a tabular summary. */
		test('shows tabular summary of proposed changes', () => {
			// Given remediations
			const remediations = [
				buildRemediation(),
				buildRemediation({
					purl: 'pkg:maven/com.example/lib@1.0.0',
					groupId: 'com.example',
					artifactId: 'lib',
					currentVersion: '1.0.0',
					fixedInVersion: '2.0.0',
					provider: 'snyk',
					vulnerabilities: [{ id: 'CVE-2024-00001', severity: 'HIGH', advisories: [] }],
				}),
			]

			// When generating dry-run output
			const report = generateReport(remediations, { dryRun: true })

			// Then it should contain the dry-run header and table columns
			expect(report).to.include('Proposed dependency updates:')
			expect(report).to.include(
				'| Dependency | Current | Fixed | Severity | Provider |'
			)
			expect(report).to.include('| org.apache.commons:commons-text | 1.9 | 1.10.0 |')
			expect(report).to.include('| com.example:lib | 1.0.0 | 2.0.0 |')
		})

		/** Verifies that dry-run does not include PR-specific phrasing. */
		test('does not include PR-specific phrasing', () => {
			const remediations = [buildRemediation()]

			const report = generateReport(remediations, { dryRun: true })

			expect(report).to.not.include('Security Update:')
			expect(report).to.not.include('Vulnerabilities resolved')
		})
	})

	suite('JSON format', () => {
		/** Verifies that JSON format returns valid JSON string. */
		test('returns valid JSON string of remediations', () => {
			const remediations = [buildRemediation()]

			const report = generateReport(remediations, { format: 'json' })
			const parsed = JSON.parse(report)

			expect(parsed).to.deep.equal(remediations)
		})

		/** Verifies that empty remediations produce empty JSON array. */
		test('returns empty JSON array for no remediations', () => {
			const report = generateReport([], { format: 'json' })

			expect(report).to.equal('[]')
		})

		/** Verifies that JSON format takes precedence over dry-run option. */
		test('JSON format takes precedence over dry-run option', () => {
			const remediations = [buildRemediation()]

			const report = generateReport(remediations, { format: 'json', dryRun: true })
			const parsed = JSON.parse(report)

			expect(parsed).to.deep.equal(remediations)
		})

		/** Verifies that JSON format takes precedence over groupBy option. */
		test('JSON format takes precedence over groupBy option', () => {
			const remediations = [buildRemediation()]

			const report = generateReport(remediations, { format: 'json', groupBy: 'bundle' })
			const parsed = JSON.parse(report)

			expect(parsed).to.deep.equal(remediations)
		})
	})

	suite('null/undefined vulnerabilities handling', () => {
		/** Verifies that per-dependency report handles null vulnerabilities without throwing. */
		test('per-dependency report handles null vulnerabilities', () => {
			const remediations = [buildRemediation({ vulnerabilities: null })]
			const report = generateReport(remediations)
			expect(report).to.include('Security Update:')
			expect(report).to.not.include('Vulnerabilities resolved')
		})

		/** Verifies that per-dependency report handles undefined vulnerabilities without throwing. */
		test('per-dependency report handles undefined vulnerabilities', () => {
			const remediations = [buildRemediation({ vulnerabilities: undefined })]
			const report = generateReport(remediations)
			expect(report).to.include('Security Update:')
			expect(report).to.not.include('Vulnerabilities resolved')
		})

		/** Verifies that bundled report handles null vulnerabilities without throwing. */
		test('bundled report handles null vulnerabilities', () => {
			const remediations = [buildRemediation({ vulnerabilities: null })]
			const report = generateReport(remediations, { groupBy: 'bundle' })
			expect(report).to.include('# Security Update Summary')
		})

		/** Verifies that bundled report handles undefined vulnerabilities without throwing. */
		test('bundled report handles undefined vulnerabilities', () => {
			const remediations = [buildRemediation({ vulnerabilities: undefined })]
			const report = generateReport(remediations, { groupBy: 'bundle' })
			expect(report).to.include('# Security Update Summary')
		})
	})

	suite('edge cases', () => {
		/** Verifies that null input returns a no-remediations message. */
		test('null input returns no-remediations message', () => {
			expect(generateReport(null)).to.equal('No remediations found.')
		})

		/** Verifies that empty array returns no-remediations message. */
		test('empty array returns no-remediations message', () => {
			expect(generateReport([])).to.equal('No remediations found.')
		})

		/** Verifies that undefined input returns no-remediations message. */
		test('undefined input returns no-remediations message', () => {
			expect(generateReport(undefined)).to.equal('No remediations found.')
		})
	})

	suite('divergence rendering', () => {
		/** Verifies that divergent groups render a recommended-vs-applied table. */
		test('renders divergence table when groups have divergent members', () => {
			// Given remediations with a divergent group
			const remediations = [
				buildRemediation({ fixedInVersion: '1.10.0' }),
				buildRemediation({
					purl: 'pkg:maven/org.apache.commons/commons-lang3@3.8',
					groupId: 'org.apache.commons',
					artifactId: 'commons-lang3',
					currentVersion: '3.8',
					fixedInVersion: '3.12.0',
					provider: 'trusted-content',
					source: 'redhat',
					vulnerabilities: [{ id: 'CVE-2023-11111', severity: 'HIGH', advisories: [] }],
				}),
			]
			const groups = [{
				changeKey: 'pom.xml:commons.version',
				appliedVersion: '3.12.0',
				remediations: remediations.map(r => ({ ...r, files: ['pom.xml'] })),
				edit: { path: 'pom.xml', after: '<content/>' },
				divergent: true,
			}]

			// When generating a report with groups
			const report = generateReport(remediations, { groups })

			// Then the divergence section should appear
			expect(report).to.include('### Applied version differs from some recommendations')
			expect(report).to.include('These artifacts share one version site')
			expect(report).to.include('| Artifact | Recommended | Applied |')
			expect(report).to.include('| org.apache.commons:commons-text | 1.10.0 | 3.12.0 |')
			expect(report).to.include('| org.apache.commons:commons-lang3 | 3.12.0 | 3.12.0 |')
		})

		/** Verifies that non-divergent groups produce no divergence section. */
		test('omits divergence section when no groups are divergent', () => {
			const remediations = [buildRemediation()]
			const groups = [{
				changeKey: 'pom.xml:direct',
				appliedVersion: '1.10.0',
				remediations: [{ ...remediations[0], files: ['pom.xml'] }],
				edit: { path: 'pom.xml', after: '<content/>' },
				divergent: false,
			}]

			const report = generateReport(remediations, { groups })

			expect(report).to.not.include('Applied version differs')
			expect(report).to.not.include('Artifact | Recommended | Applied')
		})

		/** Verifies that divergence renders in bundle mode too. */
		test('renders divergence section in bundle mode', () => {
			const remediations = [
				buildRemediation({ fixedInVersion: '1.10.0' }),
				buildRemediation({
					purl: 'pkg:maven/org.apache.commons/commons-lang3@3.8',
					groupId: 'org.apache.commons',
					artifactId: 'commons-lang3',
					currentVersion: '3.8',
					fixedInVersion: '3.12.0',
					provider: 'trusted-content',
					source: 'redhat',
					vulnerabilities: [{ id: 'CVE-2023-11111', severity: 'HIGH', advisories: [] }],
				}),
			]
			const groups = [{
				changeKey: 'pom.xml:commons.version',
				appliedVersion: '3.12.0',
				remediations: remediations.map(r => ({ ...r, files: ['pom.xml'] })),
				edit: { path: 'pom.xml', after: '<content/>' },
				divergent: true,
			}]

			const report = generateReport(remediations, { groupBy: 'bundle', groups })

			expect(report).to.include('# Security Update Summary')
			expect(report).to.include('### Applied version differs from some recommendations')
			expect(report).to.include('| org.apache.commons:commons-text | 1.10.0 | 3.12.0 |')
		})

		/** Verifies that divergence is omitted when groups option is not provided. */
		test('omits divergence section when groups option is absent', () => {
			const remediations = [buildRemediation()]

			const report = generateReport(remediations)

			expect(report).to.not.include('Applied version differs')
		})

		/** Verifies that an empty groups array produces no divergence section. */
		test('omits divergence section for empty groups array', () => {
			const remediations = [buildRemediation()]

			const report = generateReport(remediations, { groups: [] })

			expect(report).to.not.include('Applied version differs')
		})

		/** Verifies that dependencies without groupId render correctly in divergence. */
		test('renders artifactId-only names in divergence table', () => {
			const remediations = [
				buildRemediation({ groupId: '', artifactId: 'lodash', fixedInVersion: '4.17.20' }),
				buildRemediation({ groupId: '', artifactId: 'underscore', fixedInVersion: '1.13.6' }),
			]
			const groups = [{
				changeKey: 'package.json:util-version',
				appliedVersion: '1.13.6',
				remediations: remediations.map(r => ({ ...r, files: ['package.json'] })),
				edit: { path: 'package.json', after: '{}' },
				divergent: true,
			}]

			const report = generateReport(remediations, { groups })

			expect(report).to.include('| lodash | 4.17.20 | 1.13.6 |')
			expect(report).to.include('| underscore | 1.13.6 | 1.13.6 |')
		})
	})

	suite('skipped rendering', () => {
		/** Verifies that skipped remediations render a table with reasons. */
		test('renders skipped section with dependency names and reasons', () => {
			const remediations = [buildRemediation()]
			const skipped = [
				{
					groupId: 'com.example',
					artifactId: 'legacy-lib',
					newVersion: '2.0.0',
					reason: 'Shares a Maven property with excluded dependency pkg:maven/com.example/excluded',
				},
			]

			const report = generateReport(remediations, { skipped })

			expect(report).to.include('### Skipped Remediations')
			expect(report).to.include('The following remediations were not applied')
			expect(report).to.include('| Dependency | Version | Reason |')
			expect(report).to.include(
				'| com.example:legacy-lib | 2.0.0 | Shares a Maven property with excluded dependency pkg:maven/com.example/excluded |'
			)
		})

		/** Verifies that an empty skipped array produces no section. */
		test('omits skipped section for empty array', () => {
			const remediations = [buildRemediation()]

			const report = generateReport(remediations, { skipped: [] })

			expect(report).to.not.include('Skipped Remediations')
		})

		/** Verifies that skipped section is omitted when not provided. */
		test('omits skipped section when option is absent', () => {
			const remediations = [buildRemediation()]

			const report = generateReport(remediations)

			expect(report).to.not.include('Skipped Remediations')
		})

		/** Verifies that skipped renders in bundle mode. */
		test('renders skipped section in bundle mode', () => {
			const remediations = [buildRemediation()]
			const skipped = [{
				groupId: 'com.example',
				artifactId: 'old-lib',
				newVersion: '3.0.0',
				reason: 'Excluded by user',
			}]

			const report = generateReport(remediations, { groupBy: 'bundle', skipped })

			expect(report).to.include('# Security Update Summary')
			expect(report).to.include('### Skipped Remediations')
			expect(report).to.include('| com.example:old-lib | 3.0.0 | Excluded by user |')
		})

		/** Verifies that skipped dependencies without groupId render correctly. */
		test('renders artifactId-only names in skipped table', () => {
			const remediations = [buildRemediation()]
			const skipped = [{
				groupId: '',
				artifactId: 'leftpad',
				newVersion: '1.0.1',
				reason: 'Shares a version.ref with excluded dependency',
			}]

			const report = generateReport(remediations, { skipped })

			expect(report).to.include('| leftpad | 1.0.1 |')
		})
	})

	suite('combined divergence and skipped', () => {
		/** Verifies that both divergence and skipped sections render together. */
		test('renders both divergence and skipped when both present', () => {
			const remediations = [
				buildRemediation({ fixedInVersion: '1.10.0' }),
				buildRemediation({
					purl: 'pkg:maven/org.apache.commons/commons-lang3@3.8',
					groupId: 'org.apache.commons',
					artifactId: 'commons-lang3',
					currentVersion: '3.8',
					fixedInVersion: '3.12.0',
					provider: 'trusted-content',
					source: 'redhat',
					vulnerabilities: [{ id: 'CVE-2023-11111', severity: 'HIGH', advisories: [] }],
				}),
			]
			const groups = [{
				changeKey: 'pom.xml:commons.version',
				appliedVersion: '3.12.0',
				remediations: remediations.map(r => ({ ...r, files: ['pom.xml'] })),
				edit: { path: 'pom.xml', after: '<content/>' },
				divergent: true,
			}]
			const skipped = [{
				groupId: 'com.example',
				artifactId: 'dropped-lib',
				newVersion: '4.0.0',
				reason: 'Excluded',
			}]

			const report = generateReport(remediations, { groups, skipped })

			// Then both sections should appear, divergence before skipped
			expect(report).to.include('### Applied version differs from some recommendations')
			expect(report).to.include('### Skipped Remediations')
			expect(report.indexOf('Applied version differs')).to.be.lessThan(
				report.indexOf('Skipped Remediations')
			)
		})

		/** Verifies that dry-run mode does not render divergence or skipped. */
		test('dry-run mode does not render divergence or skipped', () => {
			const remediations = [buildRemediation()]
			const groups = [{
				changeKey: 'pom.xml:direct',
				appliedVersion: '1.10.0',
				remediations: [{ ...remediations[0], files: ['pom.xml'] }],
				edit: { path: 'pom.xml', after: '<content/>' },
				divergent: true,
			}]
			const skipped = [{
				groupId: 'com.example',
				artifactId: 'lib',
				newVersion: '2.0.0',
				reason: 'Excluded',
			}]

			const report = generateReport(remediations, { dryRun: true, groups, skipped })

			expect(report).to.include('Proposed dependency updates:')
			expect(report).to.not.include('Applied version differs')
			expect(report).to.not.include('Skipped Remediations')
		})

		/** Verifies that JSON format does not render divergence or skipped. */
		test('JSON format does not render divergence or skipped', () => {
			const remediations = [buildRemediation()]
			const groups = [{
				changeKey: 'pom.xml:direct',
				appliedVersion: '1.10.0',
				remediations: [{ ...remediations[0], files: ['pom.xml'] }],
				edit: { path: 'pom.xml', after: '<content/>' },
				divergent: true,
			}]

			const report = generateReport(remediations, { format: 'json', groups })
			const parsed = JSON.parse(report)

			expect(parsed).to.deep.equal(remediations)
		})
	})

	suite('deduplication key generation', () => {
		/** Verifies that the key follows the groupId:artifactId:version format. */
		test('generates key from groupId, artifactId, and fixedInVersion', () => {
			const remediation = buildRemediation()

			const key = generateDeduplicationKey(remediation)

			expect(key).to.equal('org.apache.commons:commons-text:1.10.0')
		})

		/** Verifies deterministic output for the same input. */
		test('produces identical keys for the same input', () => {
			const rem = buildRemediation()

			const key1 = generateDeduplicationKey(rem)
			const key2 = generateDeduplicationKey(rem)

			expect(key1).to.equal(key2)
		})

		/** Verifies that different versions produce different keys. */
		test('produces different keys for different versions', () => {
			const rem1 = buildRemediation({ fixedInVersion: '1.10.0' })
			const rem2 = buildRemediation({ fixedInVersion: '1.11.0' })

			expect(generateDeduplicationKey(rem1)).to.not.equal(
				generateDeduplicationKey(rem2)
			)
		})

		/** Verifies that missing groupId produces a key with leading colon. */
		test('handles missing groupId', () => {
			const rem = buildRemediation({ groupId: '' })

			const key = generateDeduplicationKey(rem)

			expect(key).to.equal(':commons-text:1.10.0')
		})

		/** Verifies that different artifacts produce different keys. */
		test('produces different keys for different artifacts', () => {
			const rem1 = buildRemediation({ artifactId: 'lib-a' })
			const rem2 = buildRemediation({ artifactId: 'lib-b' })

			expect(generateDeduplicationKey(rem1)).to.not.equal(
				generateDeduplicationKey(rem2)
			)
		})
	})
})
