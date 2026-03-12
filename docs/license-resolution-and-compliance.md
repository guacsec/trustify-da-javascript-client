# License Resolution and Compliance

This document describes the license analysis features that help you understand your project’s license and check compatibility with your dependencies.

## Overview

License analysis is **enabled by default** and provides:

1. **Project license detection** from your manifest file (e.g., `package.json`, `pom.xml`) and LICENSE files
2. **Dependency license information** from the Trustify DA backend
3. **Compatibility checking** to identify potential license conflicts
4. **Mismatch detection** when your manifest and LICENSE file declare different licenses

## How It Works

### Project License Detection

The client looks for your project’s license with **automatic fallback**:

1. **Primary: Manifest file** — Reads the license field from:
   - `package.json`: `license` field
   - `pom.xml`: `<licenses><license><name>` element
   - `Cargo.toml`: `license` field under `[package]` or `[workspace.package]`
   - `build.gradle` / `build.gradle.kts`: No standard license field (falls back to LICENSE file)
   - `go.mod`: No standard license field (falls back to LICENSE file)
   - `requirements.txt`: No standard license field (falls back to LICENSE file)

2. **Fallback: LICENSE file** — If no license is found in the manifest, searches for `LICENSE`, `LICENSE.md`, or `LICENSE.txt` in the same directory as your manifest

**How the fallback works:**
- **Ecosystems with manifest license support** (Maven, JavaScript, Rust Cargo): Uses manifest license if present, otherwise falls back to LICENSE file
- **Ecosystems without manifest license support** (Gradle, Go, Python): Automatically reads from LICENSE file
- **SPDX detection**: Common licenses (Apache-2.0, MIT, GPL-2.0/3.0, LGPL-2.1/3.0, AGPL-3.0, BSD-2-Clause/3-Clause) are automatically detected from LICENSE file content

The backend’s license identification API is used for accurate LICENSE file detection when available.

### Compatibility Checking

The client checks if dependency licenses are compatible with your project license. For example:
- Permissive project (MIT) + permissive dependencies → ✅ Compatible
- Permissive project (MIT) + strong copyleft dependency (GPL) → ⚠️ Potentially incompatible

Compatibility results are included in the analysis report’s `licenseSummary`.

## Configuration

### Disable License Checking

License analysis runs automatically during **component analysis only** (not stack analysis). To disable it:

**Environment variable:**
```bash
export TRUSTIFY_DA_LICENSE_CHECK=false
```

**Programmatic option:**
```javascript
await componentAnalysis(‘pom.xml’, { licenseCheck: false });
```

## CLI Usage

### Get License Information

```bash
exhort license path/to/pom.xml
```

**Example output:**
```json
{
  "manifestLicense": {
    "spdxId": "Apache-2.0",
    "category": "PERMISSIVE",
    "name": "Apache License 2.0",
    "identifiers": ["Apache-2.0"]
  },
  "fileLicense": {
    "spdxId": "Apache-2.0",
    "category": "PERMISSIVE",
    "name": "Apache License 2.0",
    "identifiers": ["Apache-2.0"]
  },
  "mismatch": false
}
```

Note: The `license` command shows only your project's license. For dependency license information, use component analysis.

## Analysis Report Fields

When license checking is enabled, component analysis includes a `licenseSummary` field:

```javascript
{
  // ... standard analysis fields (providers, etc.) ...
  "licenseSummary": {
    "projectLicense": {
      "manifest": {
        "spdxId": "Apache-2.0",
        "category": "PERMISSIVE",
        "name": "Apache License 2.0",
        "identifiers": ["Apache-2.0"]
      },
      "file": {
        "spdxId": "Apache-2.0",
        "category": "PERMISSIVE",
        "name": "Apache License 2.0",
        "identifiers": ["Apache-2.0"]
      },
      "mismatch": false
    },
    "incompatibleDependencies": [
      {
        "purl": "pkg:maven/org.example/gpl-lib@1.0.0",
        "licenses": ["GPL-3.0"],
        "category": "STRONG_COPYLEFT",
        "reason": "Dependency license(s) are incompatible with the project license."
      }
    ]
  }
}
```

**Note:** Dependency license information (for all dependencies, not just incompatible ones) is available in the standard backend response under the `licenses` field. The `licenseSummary` only includes project license details and flagged incompatibilities.

## Common Scenarios

### Mismatch Between Manifest and LICENSE File

If your `package.json` says `"license": "MIT"` but your LICENSE file contains Apache-2.0 text, the component analysis report will show:
```json
{
  "licenseSummary": {
    "projectLicense": {
      "manifest": {
        "spdxId": "MIT",
        "category": "PERMISSIVE",
        "name": "MIT License"
      },
      "file": {
        "spdxId": "Apache-2.0",
        "category": "PERMISSIVE",
        "name": "Apache License 2.0"
      },
      "mismatch": true
    },
    "incompatibleDependencies": []
  }
}
```

**Action:** Update your manifest or LICENSE file to match.

### Incompatible Dependencies

If you have a permissive-licensed project (MIT, Apache) but depend on GPL-licensed libraries, they’ll appear in `incompatibleDependencies`.

**Action:** Review the flagged dependencies and consider:
- Finding alternative libraries with compatible licenses
- Consulting legal counsel if the dependency is necessary
- Understanding how you’re using the dependency (linking, distribution, etc.)

## SBOM Integration

Project license information is automatically included in generated SBOMs (CycloneDX format) in the root component’s `licenses` field.

**LICENSE file fallback in SBOMs:**
- **All ecosystems** now include license information in the SBOM when available
- **Gradle, Go, Python projects**: Even though these ecosystems don’t have manifest license fields, the SBOM will include the license from your LICENSE file
- **Maven, JavaScript, Rust Cargo projects**: The SBOM uses the manifest license, or falls back to LICENSE file if not specified in manifest
- If neither manifest nor LICENSE file contains a license, the SBOM root component will have no `licenses` field
