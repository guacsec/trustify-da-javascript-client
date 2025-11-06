# Contributing to *trustify-da-javascript-client*<br/>![nodejs-version][10]

* Fork the repository
* Create a new branch
* Commit your changes
* Commits <strong>must</strong> be signed-off (see [Certificate of Origin](#certificate-of-origin))
* Create a pull request against the main branch
* Pull request titles <strong>must</strong> adhere the [Conventional Commits specification][0]

## Development

### NPM Scripts

* `npm run compile` compile all _TS_ and _JS_ code into the _dist_ folder
* `npm run lint` run eslint on _JS_ source code
* `npm run lint:fix` fix eslint issues found in _JS_ source code
* `npm run test` run unit tests,verify coverage, and print coverage info
* `npm run tests` run unit tests (no coverage)
* `npm run tests:rep` run unit tests and save the test results as _unit-tests-result.json_ (for ci)

### Good to know

* You can override the default backend url by setting another one in the _TRUSTIFY_DA_URL_ environment variable.

### OpenAPI Specifications

The OpenAPI specification is located in the [`trustify-da-api-spec`](https://github.com/trustify-da/trustify-da-api-model) where the Java and Javascript libraries are generated.

### Code Walkthrough

* [index.js](src/index.js) is the _ESM Module_ starting point. It exports 2 functions: _componentAnalysis_ and
  _stackAnalysis_. As well as the _AnalysisReport_ type imported from the _Backend_'s generated classes.
* [cli.js](src/cli.js) is the starting point of the _CLI Script_, also used when installed as a _Global Package_.
  It describes two commands: _component_ and _stack_. Use the _help_ command to get more info.
* [analysis.js](src/analysis.js) exports two functions for communicating to the _Backend_.
  The _requestComponent_ and _requestStack_ functions.
* [provider.js](src/provider.js) hosts the utility function for matching _Providers_ based on the manifest type.
  New providers needs to be listed here.
* [providers](src/providers) folder is where we place _Providers_. A _Provider_ is basically 3 functions per supported
  ecosystem.
  The _isSupported_, _provideComponent_, and _provideStack_ functions help determine the appropriate provider,
  which will provide data that we can send to the _Backend_ using _analysis.js_. See the
  [Adding a Provider](#adding-a-provider) section.
  * [java_maven.js](src/providers/java_maven.js) is the provider for the _Java_ _Maven_ ecosystem.

#### Types

This code is meant to be used as an _ESM_ module for both _JavaScript_ and _TypeScript_. So make sure you add type
declarations if needed.<br/>
Note the [sources](src) are in _JavaScript_.
Both will be compiled as an _ESM Module_ including declarations (_x.d.ts_) in the ignored _dist_ using the
`npm run compile` script and the [tsconfig.json](tsconfig.json) configuration file. Also note the _TypeScript_ files are
excluded from both linting and coverage.

#### Adding a Provider

* Add the new provider code in a designated file in the [providers'](src/providers) folder.
  A _Provider_ exports 3 functions:
  *  _isSupported_ takes a manifest name as a string, i.e. _pom.xml_ and returns _true_ if it's supported by this
    provider.
  * _provideComponent_ takes the **manifest's content** as a string and returns the ecosystem name, the content for the
    request body, and the content's type.
  * _provideStack_ takes the **manifest's path** as a string and the ecosystem name, the content for the request body,
    and the content's type.

  The data returning from the _provideX_ functions, will be passed on to the [analysis.js](src/analysis.js) for sending
  to the _Backend_.
  Use [java_maven.js](src/providers/java_maven.js) as an example to get you started.
* Import the new _Provider_ and list in the in _availableProviders_ array in [provider.js](src/provider.js).
* Update the _choices_ configuration for the _manifest-name_ positional argument in  [cli.js](src/cli.js).
* Add Integration Test scenarios for the added provider in [integration/scenarios](integration/scenarios).
  Use the [java scenarios](integration/scenarios/maven) as an example.
* Update the documentation. This document and [README.md](README.md).

### Integration Tests

Integration tests are performed with a _bash_ script executing _node_ scripts.<br/>
In [integration/run_its.sh](integration/run_its.sh) we start with a function called _match_ taking 2 arguments:
* `$1` is a file name for the holding the expected result (scenarios)
* `$2` is a command execution for evaluation (testers)

The _match_ function will match the content of the file to the output of the command.
Typically, test cases in [integration/run_its.sh](integration/run_its.sh) will invoke the _match_ function with
a scenario from the [integration/scenarios](integration/scenarios) and a _node_ command invoking one of the _node_
scripts in [integration/testers](integration/testers).<br/>

We have 3 _testers_:
* [integration/testers/cli](integration/testers/cli) is a _package.json_ used for installing the _ESM module_.
  Invoking the CLI Script is done against the _@trustify-da/trustify-da-javascript-client/dist/src/cli.js_ in the tester's
  _node_modules_.
* [integration/testers/javascript](integration/testers/javascript) is a _javascript_ script invoking the _ESM module_.
* [integration/testers/typescript](integration/testers/typescript) is a _typescript_ script invoking the _ESM module_.

Run integration tests from the project's root:

> Don't forget to run `npm run compile` before running the integration tests.

```shell
(cd integration/ && bash ./run_its.sh)
```

Integration tests are executed against a mocked _Backend_ server.<br/>
If you need to run against the actual _Backend_ server, use the _TRUSTIFY_DA_ITS_USE_REAL_API_ environment variable:

```shell
(cd integration/ && TRUSTIFY_DA_ITS_USE_REAL_API=true bash ./run_its.sh)
```

The mocked server implementation is [integration/server/mock_server.js](integration/server/mock_server.js). See the
[integration/server/mock_server_config.json](integration/server/mock_server_config.json) for configuring the mock
server.

## Certificate of Origin

By contributing to this project you agree to the Developer Certificate of
Origin (DCO). This document was created by the Linux Kernel community and is a
simple statement that you, as a contributor, have the legal right to make the
contribution. See the [DCO](DCO) file for details.

<!-- Real links -->
[0]: https://www.conventionalcommits.org/en/v1.0.0/
[1]: https://github.com/guacsec/exhort/blob/0.1.x/src/main/resources/META-INF/openapi.yaml

<!-- Badge links -->
[10]: https://badgen.net/badge/NodeJS%20Version/18/68a063
