import { expect } from 'chai'

import index from "../../src/index.js"

const packageManagersDict =
	{
		"maven" : "pom.xml",
		"npm" : "package.json",
		"pnpm": "package.json",
		"yarn-berry": "package.json",
		"yarn-classic": "package.json",
		"go" : "go.mod",
		"pip" : "requirements.txt",
		"gradle-groovy" : "build.gradle",
		"gradle-kotlin" : "build.gradle.kts"
	}

function getParsedKeyFromHtml(html, key,keyLength) {
	let beginSummary = html.substring(html.indexOf(key))
	let summary = beginSummary.substring(keyLength , beginSummary.indexOf("}") + 1);
	return JSON.parse(summary);
}

function extractTotalsGeneralOrFromProvider(providedDataForStack, provider) {
	if(providedDataForStack.providers[provider].sources && Object.keys(providedDataForStack.providers[provider].sources).length > 0) {
		// Get the first source (e.g., "osv") and return its summary total
		const firstSource = Object.keys(providedDataForStack.providers[provider].sources)[0];
		return providedDataForStack.providers[provider].sources[firstSource].summary.total;
	} else {
		return providedDataForStack.scanned.total;
	}
}

suite('Integration Tests', () => {
	[
		"gradle-groovy",
		"gradle-kotlin",
		"maven",
		"npm",
		"pnpm",
		"yarn-berry",
		"yarn-classic",
		"go",
		"pip"

	].forEach(packageManager => {
		test(`Stack Analysis json for ${packageManager}`, async () => {
			if(packageManager === "pip") {
				process.env["TRUSTIFY_DA_PYTHON_VIRTUAL_ENV"] = "true"
			} else {
				process.env["TRUSTIFY_DA_PYTHON_VIRTUAL_ENV"] = ""
			}
			process.env["TRUSTIFY_DA_DEV_MODE"] = "true"
			let manifestName = packageManagersDict[packageManager]
			let pomPath = `test/it/test_manifests/${packageManager}/${manifestName}`
			let providedDataForStack = await index.stackAnalysis(pomPath)
			console.log(JSON.stringify(providedDataForStack,null , 4))
			let providers = ["rhtpa"]
			providers.forEach(provider => expect(extractTotalsGeneralOrFromProvider(providedDataForStack, provider)).greaterThan(0))
			// TODO: if sources doesn't exist, add "scanned" instead
			// python transitive count for stack analysis is awaiting fix in exhort backend
			if(packageManager !== "pip") {
				expect(providedDataForStack.scanned.transitive).greaterThan(0)
			}
			providers.forEach(provider => expect(providedDataForStack.providers[provider].status.code).equals(200))
		}).timeout(120000);

		test(`Stack Analysis html for ${packageManager}`, async () => {
			let manifestName = packageManagersDict[packageManager]
			let pomPath = `test/it/test_manifests/${packageManager}/${manifestName}`
			let html = await index.stackAnalysis(pomPath,true)
			if(packageManager === "pip") {
				process.env["TRUSTIFY_DA_PYTHON_VIRTUAL_ENV"] = "true"
			} else {
				process.env["TRUSTIFY_DA_PYTHON_VIRTUAL_ENV"] = ""
			}
			let reportParsedFromHtml
			let parsedSummaryFromHtml
			let parsedStatusFromProvider
			let parsedScannedFromHtml
			try {
				reportParsedFromHtml = JSON.parse(html.substring(html.indexOf("\"report\" :") + 10, html.search(/([}](\s*)){5}/) + html.substring(html.search(/([}](\s*)){5}/)).indexOf(",")))
				parsedSummaryFromHtml = getParsedKeyFromHtml(html,"\"summary\"",11)
				expect(parsedSummaryFromHtml.total).greaterThanOrEqual(0)
			} catch (e) {
				let startOfJson = html.substring(html.indexOf("\"report\" :"))
				reportParsedFromHtml = JSON.parse("{" + startOfJson.substring(0,startOfJson.indexOf("};") + 1))
				reportParsedFromHtml = reportParsedFromHtml.report
			} finally {
				parsedStatusFromProvider = reportParsedFromHtml.providers["rhtpa"].status
				expect(parsedStatusFromProvider.code).equals(200)
				parsedScannedFromHtml = reportParsedFromHtml.scanned
				expect( typeof html).equals("string")
				expect(html).include("html").include("svg")
				expect(parsedScannedFromHtml.total).greaterThan(0)
				expect(parsedScannedFromHtml.transitive).greaterThan(0)
			}
		}).timeout(60000);

		test(`Component Analysis for ${packageManager}`, async () => {
			let manifestName = packageManagersDict[packageManager]
			let manifestPath = `test/it/test_manifests/${packageManager}/${manifestName}`
			const analysisReport = await index.componentAnalysis(manifestPath)

			expect(analysisReport.scanned.total).greaterThan(0)
			expect(analysisReport.scanned.transitive).equal(0)
			let providers = ["rhtpa"]
			providers.forEach(provider => expect(extractTotalsGeneralOrFromProvider(analysisReport, provider)).greaterThan(0))
			providers.forEach(provider => expect(analysisReport.providers[provider].status.code).equals(200))
		}).timeout(20000);


	});
}).beforeAll(() => process.env["TRUSTIFY_DA_DEV_MODE"] = "true");
