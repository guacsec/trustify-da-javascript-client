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

The client looks for your project’s license in two places:

1. **Manifest file** — Reads the license field from:
   - `package.json`: `license` field
   - `pom.xml`: `<licenses><license><name>` element
   - Other ecosystems: varies by ecosystem (some don’t have standard license fields)

2. **LICENSE file** — Searches for `LICENSE`, `LICENSE.md`, or `LICENSE.txt` in the same directory as your manifest

The backend’s license identification API is used for accurate LICENSE file detection.

### Dependency License Information

Dependency licenses come from the Trustify DA backend, which categorizes them as:
- **PERMISSIVE** (MIT, Apache-2.0, BSD, etc.)
- **WEAK_COPYLEFT** (LGPL, MPL, etc.)
- **STRONG_COPYLEFT** (GPL, AGPL, etc.)
- **UNKNOWN**

### Compatibility Checking

The client checks if dependency licenses are compatible with your project license. For example:
- Permissive project (MIT) + permissive dependencies → ✅ Compatible
- Permissive project (MIT) + strong copyleft dependency (GPL) → ⚠️ Potentially incompatible

Compatibility results are included in the analysis report’s `licenseSummary`.

## Configuration

### Disable License Checking

License analysis runs automatically during component/stack analysis. To disable it:

**Environment variable:**
```bash
export TRUSTIFY_DA_LICENSE_CHECK=false
```

**Programmatic option:**
```javascript
await componentAnalysis(‘pom.xml’, { licenseCheck: false });
```

### Backend URL

License analysis requires the same backend URL as dependency analysis:
```bash
export TRUSTIFY_DA_BACKEND_URL=https://api.trustify.dev
```

## CLI Usage

### Get License Information

```bash
exhort license path/to/pom.xml
```

**Example output:**
```json
{
  "projectLicense": {
    "fromManifest": "Apache-2.0",
    "fromFile": "Apache-2.0",
    "mismatch": false
  },
  "dependencies": {
    "pkg:maven/com.google.guava/guava@32.1.0": {
      "licenses": ["Apache-2.0"],
      "category": "PERMISSIVE",
      "compatible": true
    },
    "pkg:maven/org.postgresql/postgresql@42.6.0": {
      "licenses": ["BSD-2-Clause"],
      "category": "PERMISSIVE",
      "compatible": true
    }
  }
}
```

## Analysis Report Fields

When license checking is enabled, the analysis report includes:

```javascript
{
  // ... standard analysis fields ...
  "licenseSummary": {
    "projectLicenseFromManifest": "Apache-2.0",
    "projectLicenseFromFile": "Apache-2.0",
    "manifestVsFileMismatch": false,
    "incompatibleDependencies": [
      {
        "purl": "pkg:maven/org.example/gpl-lib@1.0.0",
        "licenses": ["GPL-3.0"],
        "category": "STRONG_COPYLEFT",
        "reason": "Dependency license(s) are incompatible with the project license."
      }
    ],
    "dependencyLicenses": [
      { "purl": "...", "licenses": [...], "category": "..." }
    ]
  }
}
```

## Common Scenarios

### Mismatch Between Manifest and LICENSE File

If your `package.json` says `"license": "MIT"` but your LICENSE file contains Apache-2.0 text:
```json
{
  "projectLicenseFromManifest": "MIT",
  "projectLicenseFromFile": "Apache-2.0",
  "manifestVsFileMismatch": true
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
