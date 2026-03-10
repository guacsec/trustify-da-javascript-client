# License resolution and compliance

This document describes how the client resolves the **project license** (from manifest vs repository file), how it uses the **backend licenses-by-purl endpoint** to get dependency licenses, and how **component analysis** can report when the project license is missing, inconsistent, or incompatible with dependency licenses.

## Goals

1. **Resolve project license** from:
   - The manifest (e.g. `package.json` `license`, `pom.xml` `<licenses>`) when present.
   - A `LICENSE`, `LICENSE.md`, or `LICENSE.txt` file in the same directory as the manifest.
2. **Report to the user** when the license declared in the manifest differs from the license text file.
3. **Component analysis**: when the user runs component analysis (e.g. on opening a manifest), optionally check dependency licenses (via backend) and report if any are **incompatible** with the project license.

## Resolving the project license

### From the manifest

| Ecosystem      | Manifest        | Where license is read |
|----------------|-----------------|------------------------|
| JavaScript     | package.json    | `license` (string) or `licenses` (array); can be SPDX id or "SEE LICENSE IN FILE" |
| Java (Maven)   | pom.xml         | Effective POM: `<licenses><license><name>` / `<url>`; map common names to SPDX where possible |
| Java (Gradle)  | build.gradle(*) | No standard; some projects set extra/license in properties; optional best-effort |
| Go             | go.mod          | No standard license field |
| Python         | requirements.txt| No license in manifest |

(*) Gradle: license is often in a separate file or NOTICE; we do not parse build logic.

### From the repository (LICENSE / LICENSE.md)

- Look in the **manifest directory** for `LICENSE`, `LICENSE.md`, or `LICENSE.txt`.
- Only searches the same directory as the manifest (not parent directories or git root).
- Read file content; try to **detect** or **normalize** to an SPDX identifier (e.g. "Apache-2.0") for comparison using local pattern matching or the backend `/licenses/identify` endpoint for more accuracy.

### Reporting manifest vs file mismatch

- If both manifest and file are present and indicate different licenses → set `licenseSummary.manifestVsFileMismatch: true` and include both values so the user can fix the inconsistency.
- If only one is present, we still expose both `fromManifest` and `fromFile` so the user sees what was found.

## Backend: License Analysis API (v5) and license data in the analysis report

The Trustify Dependency Analytics backend provides:

1. **License data in the dependency analysis report** — When using the analysis API (e.g. stack or component analysis), the JSON report includes a **`licenses`** field with license information for all dependencies. This is a **LicensesResponse**: an array of provider results, each with `status`, `summary`, and `packages` (object keyed by purl). Each package has `concluded` (with `identifiers`, `expression`, `name`, `category`) and `evidence`. Categories are: **PERMISSIVE**, **WEAK_COPYLEFT**, **STRONG_COPYLEFT**, **UNKNOWN** (see [OpenAPI v5](https://github.com/guacsec/trustify-da-api-spec/blob/main/api/v5/openapi.yaml)).

2. **License identification endpoint** — `POST /licenses/identify` accepts a LICENSE file (binary/text) and returns the identified SPDX license. This is used to accurately identify the project's LICENSE file when more precision is needed than local pattern matching.

3. **License details endpoint** — `GET /api/v5/licenses/{spdx}` returns detailed information about a specific license by SPDX identifier, including `category`, `name`, `identifiers`, `expression`, `source`, etc. Used by the CLI `license` command to provide rich license information.

The client:

- When running the license check **after component analysis**, it uses the `result.licenses` data from the analysis response (no extra request needed for dependency licenses).
- For the **project LICENSE file**, it first attempts local pattern matching (fast, synchronous). During the license check (async), it can optionally call `POST /licenses/identify` for more accurate backend-based identification.
- Normalizes the license response into a map of purl → `{ licenses: string[], category? }` and uses the backend **category** for compatibility checking (e.g. project permissive + dependency STRONG_COPYLEFT → incompatible).

## Component analysis: license incompatibility report

When the user runs **component analysis** (e.g. upon opening a manifest):

1. The client builds the SBOM (direct dependencies only) and sends it to the backend for the usual component analysis.
2. By default or unless `TRUSTIFY_DA_LICENSE_CHECK=false` or an option like `licenseCheck: false` is set:
   - **Resolve project license** from manifest (synchronous).
   - If a LICENSE file exists, optionally call `POST /licenses/identify` to accurately identify it via the backend.
   - Set `licenseSummary.manifestVsFileMismatch` if manifest and LICENSE file licenses differ.
   - **Extract purls** from the SBOM that was sent (from `provided.content`).
   - **Get dependency licenses** from the analysis result’s `licenses` array (already included in the response).
   - For each dependency, determine if its license(s) are **compatible** with the project license, using the backend category (PERMISSIVE / WEAK_COPYLEFT / STRONG_COPYLEFT).
   - Attach a **license summary** to the component analysis result, e.g.:
     - `licenseSummary.projectLicenseFromManifest`
     - `licenseSummary.projectLicenseFromFile`
     - `licenseSummary.manifestVsFileMismatch`
     - `licenseSummary.incompatibleDependencies`: `[{ purl, licenses, category, reason }]`
     - `licenseSummary.dependencyLicenses`: `[{ purl, licenses, category }]`
     - So the user can see which dependencies have licenses incompatible with the project license.

The client uses the backend **category** from the analysis report’s `licenses` field, plus a small in-client compatibility matrix (e.g. permissive project + STRONG_COPYLEFT dependency → incompatible).

## Disabling the license check in component analysis

- **Environment variable**: `TRUSTIFY_DA_LICENSE_CHECK=false`
- **Option**: `opts.licenseCheck = false` when calling `client.componentAnalysis(manifest, opts)`

By default (unless disabled), after the component analysis response is received, the client:
1. Resolves the project license from manifest and LICENSE file (with optional backend identification for LICENSE file)
2. Extracts dependency licenses from `result.licenses` in the analysis response
3. Computes compatibility and attaches a `licenseSummary` to the report

## API surface (client)

- **Project license resolution** (local, synchronous):
  - `getProjectLicense(manifestPath, opts)` → `{ fromManifest, fromFile, mismatch }`
  - `getProjectLicenseFromManifestOnly(manifestPath, opts)` → `{ fromManifest, fromFile: null, mismatch: false }`
  - `findLicenseFilePath(manifestPath)` → `string|null` (path to LICENSE file)

- **Backend license identification and details**:
  - `identifyLicenseViaBackend(licenseFilePath, backendUrl, opts)` → `Promise<string|null>` (SPDX id from `POST /licenses/identify`)
  - `getLicenseDetails(spdxId, backendUrl, opts)` → `Promise<Object|null>` (detailed license info from `GET /api/v5/licenses/{spdx}`, includes category, name, identifiers, etc.)

- **Dependency licenses from analysis report**:
  - `licenseMapFromAnalysisReport(analysisReport, purls?)` → `Map<purl, { licenses, category? }>`
  - Extracts license data from the analysis response's `licenses` field (no extra request)

- **Full license check** (for component analysis):
  - `runLicenseCheck(sbomContent, manifestPath, backendUrl, opts, analysisResult)` → `Promise<LicenseSummary>`
  - Uses `analysisResult.licenses` for dependency licenses. Optionally calls `POST /licenses/identify` for accurate project LICENSE file identification. Used inside `componentAnalysis()` when license check is enabled; result is attached as `report.licenseSummary`.

- **Compatibility checking**:
  - `getCompatibility(projectLicense, dependencyLicenses[], dependencyCategory?)` → `'compatible' | 'incompatible' | 'unknown'`

- **Utility** (typically not needed):
  - `getLicensesByPurl(purls, backendUrl, opts)` → `Promise<Map<purl, { licenses, category? }>>` (standalone call to `POST /api/v5/licenses`)

Options (e.g. proxy, token) are passed through to the backend fetch in the same way as for analysis requests.
