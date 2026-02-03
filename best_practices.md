
<b>Pattern 1: Prefer invoking external tools via a centralized helper that accepts a binary plus an args array (not shell strings), and wrap failures with a consistent, user-facing error message while attaching the original error via `{ cause: error }`.
</b>

Example code before:
```
import { execSync } from "node:child_process";

function runPip(pipBin, depNames) {
  // shell string + loses original error context
  return execSync(`${pipBin} show ${depNames.join(" ")}`).toString();
}
```

Example code after:
```
import { invokeCommand } from "./tools.js";

function runPip(pipBin, depNames) {
  try {
    return invokeCommand(pipBin, ["show", ...depNames], { stdio: "pipe" }).toString("utf-8");
  } catch (error) {
    throw new Error("Failed to invoke 'pip show' to fetch package metadata.", { cause: error });
  }
}
```

<details><summary>Examples for relevant past discussions:</summary>

- https://github.com/guacsec/trustify-da-javascript-client/pull/185#discussion_r2058479181
- https://github.com/guacsec/trustify-da-javascript-client/pull/159#discussion_r2029025976
- https://github.com/guacsec/trustify-da-javascript-client/pull/206#discussion_r2100328541
</details>


___

<b>Pattern 2: Avoid global process state changes (like `process.chdir`) for cross-platform command execution; prefer passing `cwd`/`env` via subprocess options, and use OS-correct primitives (e.g., `path.delimiter`) when manipulating PATH.
</b>

Example code before:
```
const originalDir = process.cwd();
process.chdir(projectDir);
try {
  invokeCommand("npm", ["install"]);
} finally {
  process.chdir(originalDir);
}

process.env.PATH = `${extraPaths.join(":")}:${process.env.PATH}`;
```

Example code after:
```
invokeCommand("npm", ["install"], { cwd: projectDir });

const newPath = `${extraPaths.join(path.delimiter)}${path.delimiter}${process.env.PATH}`;
invokeCommand("node", ["--version"], { env: { ...process.env, PATH: newPath } });
```

<details><summary>Examples for relevant past discussions:</summary>

- https://github.com/guacsec/trustify-da-javascript-client/pull/182#discussion_r2057977443
- https://github.com/guacsec/trustify-da-javascript-client/pull/191#discussion_r2068393651
- https://github.com/guacsec/trustify-da-javascript-client/pull/206#discussion_r2100324334
</details>


___

<b>Pattern 3: Make CI/release automation deterministic and non-recursive: ensure workflows don’t trigger themselves (tag/branch loops), generate EA/dev versions at build time (e.g., `-ea.<short_sha>`), and keep workflow comments and conditions aligned with actual behavior.
</b>

Example code before:
```
on:
  push:
    tags: ["*"]  # too broad, may trigger unintended publishes

# For branch pushes, use -dev suffix
VERSION="${BASE}-dev"
git tag "$VERSION"
git push origin "$VERSION"  # can trigger same workflow again
```

Example code after:
```
on:
  push:
    tags: ["v*.*.*"]  # only release tags

# For main EA builds, use -ea.<short_sha> suffix
BASE=$(node -p "require('./package.json').version" | sed -E 's/-ea[.-][0-9]+$//')
SHORT_SHA=$(git rev-parse --short "${GITHUB_SHA}")
VERSION="${BASE}-ea.${SHORT_SHA}"

# Avoid creating/pushing tags from workflows unless explicitly required
```

<details><summary>Examples for relevant past discussions:</summary>

- https://github.com/guacsec/trustify-da-javascript-client/pull/274#discussion_r2533854698
- https://github.com/guacsec/trustify-da-javascript-client/pull/277#discussion_r2534926978
- https://github.com/guacsec/trustify-da-javascript-client/pull/276#discussion_r2534393333
</details>


___

<b>Pattern 4: Keep configuration and terminology explicit and externally configurable: avoid hardcoded endpoints/ambiguous docs, prefer clear environment variable naming, and only set/emit optional request parameters when they change behavior (e.g., send `recommend=false` only when disabled).
</b>

Example code before:
```
// Hardcoded backend + ambiguous docs
const BACKEND = "https://example.stage.internal";
// "task param" (unclear) in README

// Always send recommend param even when default
const finalUrl = `${url}/api/v4/analysis?recommend=true`;
```

Example code after:
```
// Backend configured via env/opts with documented precedence
const backend = getCustom("TRUSTIFY_DA_BACKEND_URL", "https://prod.example.com", opts);

// Only include query parameter when disabling recommendations
const finalUrl = new URL(`${backend}/api/v4/analysis`);
if (opts.TRUSTIFY_DA_RECOMMENDATIONS_ENABLED === "false") {
  finalUrl.searchParams.set("recommend", "false");
}
```

<details><summary>Examples for relevant past discussions:</summary>

- https://github.com/guacsec/trustify-da-javascript-client/pull/353#discussion_r2708314483
- https://github.com/guacsec/trustify-da-javascript-client/pull/249#discussion_r2499762275
- https://github.com/guacsec/trustify-da-javascript-client/pull/233#discussion_r2157547122
</details>


___
