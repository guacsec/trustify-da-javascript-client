# JavaScript lockfile reference SBOMs

The `expected_stack_sbom.json` and `expected_component_sbom.json` files are compared
in full by `test/javascript_lockfile.test.js`, with timestamps fixed to
2023-08-07T00:00:00.000Z and only component/edge ordering normalized.

The reference listings were captured from copies of the complete fixtures using:

- npm 10.9.8: `npm ls --package-lock-only --omit=dev --json` with `--all` or `--depth=0`.
- Yarn 1.22.22: `yarn list --prod --frozen-lockfile --offline --json` with
  `--depth=Infinity` or `--depth=0`.
- Yarn 4.9.3: `yarn info --all --json`, adding `--recursive` for stack analysis.

Corepack auto-pinning and network access were disabled. Berry's install state was
redirected outside the copied fixture. No installation was needed to capture the
listings. The former provider implementation converted those listings into the
reference SBOMs, including root metadata, ignore handling, and lockfile hashes.

All npm cases, component cases, small mixed-dependency cases, and workspace-member
cases matched the new implementation exactly. The larger Yarn stack references
include these explicitly checked corrections to the former conversion:

- Classic shadowed dependencies resolve through their lockfile selectors. The
  former processor's global map keyed only by package name mixed versions and
  created incorrect edges. For example, `debug@3.1.0` requires `ms@2.0.0`, not
  another branch's `ms@2.1.3`.
- Berry patches retain the original package identity (`fsevents@2.3.3`) rather
  than treating `fsevents@patch:fsevents` as a package name. The dependency from
  chokidar and the patch's lockfile checksum are retained.
- Berry peer edges are reconstructed in the requesting package's context. This
  retains the fdir/picomatch and mongoose-legacy-pluralize/mongoose relationships
  present in the lockfile but dropped by the former processor.
- Registry aliases use the canonical locked identity for hash lookup, retaining
  the recorded checksum for `wrap-ansi@7.0.0`.

The small parser tests independently cover version-specific edges, aliases,
patch checksums, distinct peer contexts, and cycles. The mixed/workspace locks
that previously contained only a header are now complete small graph fixtures;
development nodes are present for consistency validation and excluded from the
production SBOM.

Resolution matching follows the package managers' published rules:

- [npm overrides](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#overrides)
  and [Arborist's matching implementation](https://github.com/npm/cli/blob/latest/workspaces/arborist/lib/override-set.js).
- [Berry resolution selectors](https://yarnpkg.com/configuration/manifest#resolutions)
  and [its CorePlugin implementation](https://github.com/yarnpkg/berry/blob/master/packages/yarnpkg-core/sources/CorePlugin.ts).
- [Classic resolution paths](https://github.com/yarnpkg/yarn/blob/master/src/resolution-map.js).

Unsupported protocols and missing metadata fail explicitly. Cycles work with
ordinary and global Classic resolutions; cycles combined with path-dependent
Classic resolution patterns are rejected because their ancestry cannot be
reconstructed reliably from the lockfile. This path does not run Yarn plugins
or validate archive contents, installation scripts, or the installed tree.
