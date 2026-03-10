# Trustify Dependency Analytics JavaScript Client<br/>![latest-no-snapshot][0] ![latest-snapshot][1]

* Looking for the OpenAPI Spec? Try [Trustify Dependency Analytics API](https://github.com/guacsec/trustify-da-api-spec)
* Looking for our Java API? Try [Trustify Dependency Analytics Java Client](https://github.com/guacsec/trustify-da-java-client).
* Looking for our Backend implementation? Try [Trustify Dependency Analytics](https://github.com/guacsec/trustify-dependency-analytics).

<h3>Usage</h3>
<p>

<strong>Prerequisites:</strong> The <code>TRUSTIFY_DA_BACKEND_URL</code> environment variable must be set to the URL of the Trustify Dependency Analytics backend service. You can set it as an environment variable or pass it in the options object (see <a href="#customization">Customization</a> section).

<ul>
<li>
Use as ESM Module from an ESM module

```shell
npm install @trustify-da/trustify-da-javascript-client
```

```shell
# Set the mandatory backend URL
export TRUSTIFY_DA_BACKEND_URL=https://trustify-da.example.com
```

```javascript
import client from '@trustify-da/trustify-da-javascript-client'
import fs from 'node:fs'

// Get stack analysis in JSON format
let stackAnalysis = await client.stackAnalysis('/path/to/pom.xml')
// Get stack analysis in HTML format (string)
let stackAnalysisHtml = await client.stackAnalysis('/path/to/pom.xml', true)
// Get component analysis in JSON format
let componentAnalysis = await client.componentAnalysis('/path/to/pom.xml')
// Get image analysis in JSON format
let imageAnalysis = await client.imageAnalysis(['docker.io/library/node:18'])
// Get image analysis in HTML format (string)
let imageAnalysisHtml = await client.imageAnalysis(['docker.io/library/node:18'], true)
// Analyze multiple images
let multipleImagesAnalysis = await client.imageAnalysis(['docker.io/library/node:18', 'docker.io/library/python:3.9'])
// Specify architecture using ^^ notation (e.g., httpd:2.4.49^^amd64)
let imageAnalysisWithArch = await client.imageAnalysis(['httpd:2.4.49^^amd64'])
```
</li>
</ul>
<ul>
<li>
Use as ESM Module from Common-JS module

```shell
npm install @trustify-da/trustify-da-javascript-client
```

```javascript
async function loadTrustifyDa()
{
// dynamic import is the only way to import ESM module into commonJS module
  const { default: client } = await import('@trustify-da/trustify-da-javascript-client');
  return client
}
const runTrustifyDa = (manifestPath) => {
  return new Promise(async ( resolve, reject) => {
    try {
      let stackAnalysisReport = await (await loadTrustifyDa()).stackAnalysis(manifestPath,false)
      resolve(stackAnalysisReport)

    } catch (error)
    {
      reject(error)
    }
  });
};

runTrustifyDa("./path/to/manifest").then(resp => console.log(JSON.stringify(resp,null,4)))
```
</li>

<li>
Use as CLI Script
<details>
<summary>Click for help menu</summary>

```shell
$ npx @trustify-da/trustify-da-javascript-client help

Usage: trustify-da-javascript-client {component|stack|image|validate-token|license}

Commands:
  trustify-da-javascript-client stack </path/to/manifest> [--html|--summary]               produce stack report for manifest path
  trustify-da-javascript-client component <path/to/manifest> [--summary]   produce component report for a manifest type and content
  trustify-da-javascript-client image <image-refs..> [--html|--summary]               produce image analysis report for OCI image references
  trustify-da-javascript-client license </path/to/manifest>               display project license information from manifest and LICENSE file in JSON format

Options:
  --help  Show help                                                    [boolean]
```
</details>

```shell
# get stack analysis in json format
$ npx @trustify-da/trustify-da-javascript-client stack /path/to/pom.xml

# get stack analysis in json format (summary only)
$ npx @trustify-da/trustify-da-javascript-client stack /path/to/pom.xml --summary

# get stack analysis in html format format
$ npx @trustify-da/trustify-da-javascript-client stack /path/to/pom.xml --html

# get component analysis
$ npx @trustify-da/trustify-da-javascript-client component /path/to/pom.xml

# get image analysis in json format
$ npx @trustify-da/trustify-da-javascript-client image docker.io/library/node:18

# get image analysis in json format (summary only)
# Note: summary returns an object with imageRef as key
$ npx @trustify-da/trustify-da-javascript-client image docker.io/library/node:18 --summary

# get image analysis in html format
$ npx @trustify-da/trustify-da-javascript-client image docker.io/library/node:18 --html

# analyze multiple images
$ npx @trustify-da/trustify-da-javascript-client image docker.io/library/node:18 docker.io/library/python:3.9

# specify architecture using ^^ notation (e.g., httpd:2.4.49^^amd64)
$ npx @trustify-da/trustify-da-javascript-client image httpd:2.4.49^^amd64

# get project license information
$ npx @trustify-da/trustify-da-javascript-client license /path/to/package.json
```
</li>

<li>
Use as Global Binary

```shell
npm install --global @trustify-da/trustify-da-javascript-client
```

```shell
# get stack analysis in json format
$ trustify-da-javascript-client stack /path/to/pom.xml

# get stack analysis in json format (summary only)
$ trustify-da-javascript-client stack /path/to/pom.xml --summary

# get stack analysis in html format format
$ trustify-da-javascript-client stack /path/to/pom.xml --html

# get component analysis
$ trustify-da-javascript-client component /path/to/pom.xml

# get image analysis in json format
$ trustify-da-javascript-client image docker.io/library/node:18

# get image analysis in json format (summary only)
# Note: summary returns an object with imageRef as key
$ trustify-da-javascript-client image docker.io/library/node:18 --summary

# get image analysis in html format
$ trustify-da-javascript-client image docker.io/library/node:18 --html

# analyze multiple images
$ trustify-da-javascript-client image docker.io/library/node:18 docker.io/library/python:3.9

# specify architecture using ^^ notation (e.g., httpd:2.4.49^^amd64)
$ trustify-da-javascript-client image httpd:2.4.49^^amd64

# get project license information
$ trustify-da-javascript-client license /path/to/package.json
```
</li>
</ul>

<h3>Supported Ecosystems</h3>
<ul>
<li><a href="https://www.java.com/">Java</a> - <a href="https://maven.apache.org/">Maven</a></li>
<li><a href="https://www.javascript.com/">JavaScript</a> - <a href="https://www.npmjs.com/">Npm</a></li>
<li><a href="https://www.javascript.com/">JavaScript</a> - <a href="https://pnpm.io/">pnpm</a></li>
<li><a href="https://www.javascript.com/">JavaScript</a> - <a href="https://classic.yarnpkg.com/">Yarn Classic</a> /  <a href="https://yarnpkg.com/">Yarn Berry</a></li>
<li><a href="https://go.dev/">Golang</a> - <a href="https://go.dev/blog/using-go-modules/">Go Modules</a></li>
<li><a href="https://www.python.org/">Python</a> - <a href="https://pypi.org/project/pip/">pip Installer</a></li>
<li><a href="https://gradle.org/">Gradle (Groovy and Kotlin DSL)</a> - <a href="https://gradle.org/install/">Gradle Installation</a></li>
</ul>

<h3>Excluding Packages</h3>
<p>
Excluding a package from any analysis can be achieved by marking the package for exclusion.
</p>

<ul>
<li>
<em>Java Maven</em> users can add a comment in <em>pom.xml</em>

```xml
<dependency> <!--exhortignore-->
  <groupId>...</groupId>
  <artifactId>...</artifactId>
  <version>...</version>
</dependency>
```
</li>

</ul>
<ul>
<li>
<em>Javascript</em> users can add a root (key, value) pair with value of list of names (strings) to be ignored (without versions), and key called <b>exhortignore</b> in <em>package.json</em>,  example:

```json
{
  "name": "sample",
  "version": "1.0.0",
  "description": "",
  "main": "js",
  "keywords": [],
  "author": "",
  "license": "ISC",
  "dependencies": {
    "dotenv": "^8.2.0",
    "express": "^4.17.1",
    "jsonwebtoken": "^8.5.1",
    "mongoose": "^5.9.18"
  },
  "exhortignore": [
    "jsonwebtoken"
  ]
}
```

<em>Golang</em> users can add in go.mod a comment with //exhortignore next to the package to be ignored, or to "piggyback" on existing comment ( e.g - //indirect) , for example:
```go
module github.com/trustify-da/SaaSi/deployer

go 1.19

require (
        github.com/gin-gonic/gin v1.9.1
        github.com/google/uuid v1.1.2
        github.com/jessevdk/go-flags v1.5.0 //exhortignore
        github.com/kr/pretty v0.3.1
        gopkg.in/yaml.v2 v2.4.0
        k8s.io/apimachinery v0.26.1
        k8s.io/client-go v0.26.1
)

require (
        github.com/davecgh/go-spew v1.1.1 // indirect exhortignore
        github.com/emicklei/go-restful/v3 v3.9.0 // indirect
        github.com/go-logr/logr v1.2.3 // indirect //exhortignore

)
```

<em>Python pip</em> users can add in requirements.txt a comment with #exhortignore(or # exhortignore) to the right of the same artifact to be ignored, for example:
```properties
anyio==3.6.2
asgiref==3.4.1
beautifulsoup4==4.12.2
certifi==2023.7.22
chardet==4.0.0
click==8.0.4 #exhortignore
contextlib2==21.6.0
fastapi==0.75.1
Flask==2.0.3
h11==0.13.0
idna==2.10
immutables==0.19
importlib-metadata==4.8.3
itsdangerous==2.0.1
Jinja2==3.0.3
MarkupSafe==2.0.1
pydantic==1.9.2 # exhortignore
requests==2.25.1
six==1.16.0
sniffio==1.2.0
soupsieve==2.3.2.post1
starlette==0.17.1
typing_extensions==4.1.1
urllib3==1.26.16
uvicorn==0.17.0
Werkzeug==2.0.3
zipp==3.6.0

```

<em>Gradle</em> users can add in build.gradle a comment with //exhortignore next to the package to be ignored:
```build.gradle
plugins {
id 'java'
}

group = 'groupName'
version = 'version'

repositories {
    mavenCentral()
}

dependencies {
    implementation "groupId:artifactId:version" // exhortignore
}
test {
    useJUnitPlatform()
}
```

All of the 5 above examples are valid for marking a package to be ignored
</li>

</ul>

<h3>Customization</h3>
<p>
There are 2 approaches for customizing <em>Trustify Dependency Analytics JavaScript Client</em>. Whether you're using this API as a
<em>Global Module</em>, a <em>Remote Script</em>, or an <em>ESM Module</em>, you can use <em>Environment Variables</em>
for various customization.

<strong>Note:</strong> The <code>TRUSTIFY_DA_BACKEND_URL</code> environment variable is <strong>mandatory</strong> and must be set to the URL of the Trustify Dependency Analytics backend service. Without this variable, the API will throw an error.

However, <em>ESM Module</em> users, can opt for customizing programmatically:

```javascript
import client from '@trustify-da/trustify-da-javascript-client'
import fs from 'node:fs'

let options = {
  // Mandatory: Backend URL for Trustify Dependency Analytics service
  'TRUSTIFY_DA_BACKEND_URL': 'https://api.trustify.dev',
  'TRUSTIFY_DA_MVN_PATH': '/path/to/my/mvn',
  'TRUSTIFY_DA_NPM_PATH': '/path/to/npm',
  'TRUSTIFY_DA_PNPM_PATH': '/path/to/pnpm',
  'TRUSTIFY_DA_GO_PATH': '/path/to/go',
  //python - python3, pip3 take precedence if python version > 3 installed
  'TRUSTIFY_DA_PYTHON3_PATH' : '/path/to/python3',
  'TRUSTIFY_DA_PIP3_PATH' : '/path/to/pip3',
  'TRUSTIFY_DA_PYTHON_PATH' : '/path/to/python',
  'TRUSTIFY_DA_PIP_PATH' : '/path/to/pip',
  'TRUSTIFY_DA_GRADLE_PATH' : '/path/to/gradle',
  // Configure proxy for all requests
  'TRUSTIFY_DA_PROXY_URL': 'http://proxy.example.com:8080'
}

// Get stack analysis in JSON format ( all package managers, pom.xml is as an example here)
let stackAnalysis = await client.stackAnalysis('/path/to/pom.xml', false, options)
// Get stack analysis in HTML format in string ( all package managers, pom.xml is as an example here)
let stackAnalysisHtml = await client.stackAnalysis('/path/to/pom.xml', true, options)

// Get component analysis in JSON format
let componentAnalysis = await client.componentAnalysis('/path/to/pom.xml', options)

// Get image analysis in JSON format
let imageAnalysis = await client.imageAnalysis(['docker.io/library/node:18'], false, options)
// Get image analysis in HTML format in string
let imageAnalysisHtml = await client.imageAnalysis(['docker.io/library/node:18'], true, options)
// Specify architecture using ^^ notation (e.g., httpd:2.4.49^^amd64)
let imageAnalysisWithArch = await client.imageAnalysis(['httpd:2.4.49^^amd64'], false, options)
```
 **_Environment variables takes precedence._**
</p>

<h4>Proxy Configuration</h4>
<p>
You can configure a proxy for all HTTP/HTTPS requests made by the API. This is useful when your environment requires going through a proxy to access external services.

You can set the proxy URL in two ways:

1. Using environment variable:
```shell
export TRUSTIFY_DA_PROXY_URL=http://proxy.example.com:8080
```

2. Using the options object when calling the API programmatically:
```javascript
const options = {
  'TRUSTIFY_DA_PROXY_URL': 'http://proxy.example.com:8080'
}
```

The proxy URL should be in the format: `http://host:port` or `https://host:port`. The API will automatically use the appropriate protocol (HTTP or HTTPS) based on the proxy URL provided.
</p>

<h4>License resolution and dependency license compliance</h4>
<p>
The client can resolve the <strong>project license</strong> from the manifest (e.g. <code>package.json</code> <code>license</code>, <code>pom.xml</code> <code>&lt;licenses&gt;</code>) and from a <code>LICENSE</code> or <code>LICENSE.md</code> file in the project, and report when they differ. For <strong>component analysis</strong>, you can optionally run a license check: the client fetches dependency licenses from the backend (by purl) and reports dependencies whose licenses are incompatible with the project license. See <a href="docs/license-resolution-and-compliance.md">License resolution and compliance</a> for design and behavior. To disable the check on component analysis, set <code>TRUSTIFY_DA_LICENSE_CHECK=false</code> or pass <code>licenseCheck: false</code> in the options.
</p>

<h4>Customizing Executables</h4>
<p>
This project uses each ecosystem's executable for creating dependency trees. These executables are expected to be
present on the system's PATH environment. If they are not, or perhaps you want to use custom ones. Use can use the
following keys for setting custom paths for the said executables.
</p>

<table>
<tr>
<th>Ecosystem</th>
<th>Default</th>
<th>Executable Key</th>
</tr>
<tr>
<td><a href="https://maven.apache.org/">Maven</a></td>
<td><em>mvn</em></td>
<td>TRUSTIFY_DA_MVN_PATH</td>
</tr>
<tr>
<td><a href="https://maven.apache.org/">Maven</a></td>
<td><em>maven</em></td>
<td>TRUSTIFY_DA_PREFER_MVNW</td>
</tr>
<tr>
<td><a href="https://www.npmjs.com/">NPM</a></td>
<td><em>npm</em></td>
<td>TRUSTIFY_DA_NPM_PATH</td>
</tr>
<tr>
<td><a href="https://pnpm.io/">PNPM</a></td>
<td><em>pnpm</em></td>
<td>TRUSTIFY_DA_PNPM_PATH</td>
</tr>
<tr>
<td><a href="https://classic.yarnpkg.com/">Yarn Classic</a> / <a href="https://yarnpkg.com/">Yarn Berry</a></td>
<td><em>yarn</em></td>
<td>TRUSTIFY_DA_YARN_PATH</td>
</tr>
<tr>
<td><a href="https://go.dev/blog/using-go-modules/">Go Modules</a></td>
<td><em>go</em></td>
<td>TRUSTIFY_DA_GO_PATH</td>
</tr>
<tr>
<td><a href="https://www.python.org/">Python programming language</a></td>
<td><em>python3</em></td>
<td>TRUSTIFY_DA_PYTHON3_PATH</td>
</tr>
<tr>
<td><a href="https://pypi.org/project/pip/">Python pip Package Installer</a></td>
<td><em>pip3</em></td>
<td>TRUSTIFY_DA_PIP3_PATH</td>
</tr>
<tr>
<td><a href="https://www.python.org/">Python programming language</a></td>
<td><em>python</em></td>
<td>TRUSTIFY_DA_PYTHON_PATH</td>
</tr>
<tr>
<td><a href="https://pypi.org/project/pip/">Python pip Package Installer</a></td>
<td><em>pip</em></td>
<td>TRUSTIFY_DA_PIP_PATH</td>
</tr>
<tr>
<td><a href="https://gradle.org/">Gradle</a></td>
<td><em>gradle</em></td>
<td>TRUSTIFY_DA_GRADLE_PATH</td>
</tr>
<tr>
<td><a href="https://gradle.org/">Gradle</a></td>
<td><em>gradle</em></td>
<td>TRUSTIFY_DA_PREFER_GRADLEW</td>
</tr>
</table>

#### Match Manifest Versions Feature

##### Background

In Python pip and in golang go modules package managers ( especially in Python pip) , There is a big chance that for a certain manifest and a given package inside it, the client machine environment has different version installed/resolved
for that package, which can lead to perform the analysis on the installed packages' versions , instead on the declared versions ( in manifests - that is requirements.txt/go.mod ), and this
can cause a confusion for the user in the client consuming the API and leads to inconsistent output ( in THE manifest there is version X For a given Package `A` , and in the analysis report there is another version for the same package `A` - Y).

##### Usage

To eliminate confusion and improve clarity as discussed above, the following setting was introduced - `MATCH_MANIFEST_VERSIONS`, in the form of environment variable/key in opts ( as usual , environment variable takes precedence )
for two ecosystems:
 - Golang - Go Modules
 - Python - pip

Two possible values for this setting:

1. MATCH_MANIFEST_VERSIONS="false" - means that if installed/resolved versions of packages are different than the ones declared in the manifest, the process will ignore this difference and will continue to analysis with installed/resolved versions ( this is the original logic flow )
<br>


2. MATCH_MANIFEST_VERSIONS="true" - means that before starting the analysis,
   the api will compare all the versions of packages in manifest against installed/resolved versions on client' environment, in case there is a difference, it will throw an error to the client/user with message containing the first encountered versions mismatch, including package name, and the versions difference, and will suggest to set setting `MATCH_MANIFEST_VERSIONS`="false" to ignore all differences

#### Golang Support

By default, Golang dependency resolution follows the [Minimal Version Selection (MVS) Algorithm](https://go.dev/ref/mod#minimal-version-selection).
This means that when analyzing a project, only the module versions that would actually be included in the final executable are considered.

For example, if your `go.mod` file declares two modules, `a` and `b`, and both depend on the same package `c` (same major version `v1`) but with different minor versions:

- `namespace/c/v1@v1.1`
- `namespace/c/v1@v1.2`

Only one of these versions — the minimal version selected by MVS — will be included in the generated SBOM and analysis results.
This mirrors the behavior of a real Go build, where only one minor version of a given major version can be present in the executable (since Go treats packages with the same name and major version as identical).

The MVS-based resolution is **enabled by default**.
If you want to disable this behavior and instead include **all transitive module versions** (as listed in `go.mod` dependencies), set the system property or environment variable:

```bash
TRUSTIFY_DA_GO_MVS_LOGIC_ENABLED=false
```

#### Python Support

By default, For python support, the api assumes that the package is installed using the pip/pip3 binary on the system PATH, or using the customized
Binaries passed to environment variables. In any case, If the package is not installed , then an error will be thrown.

There is an experimental feature of installing the requirements.txt on a virtual env(only python3 or later is supported for this feature) - in this case,
it's important to pass in a path to python3 binary as `TRUSTIFY_DA_PYTHON3_PATH` or instead make sure that python3 is on the system path.
in such case, You can use that feature by setting environment variable `TRUSTIFY_DA_PYTHON_VIRTUAL_ENV` to true.

##### "Best Efforts Installation"
Since Python pip packages are very sensitive/picky regarding python version changes( every small range of versions is only tailored for a certain python version), I'm introducing this feature, that
tries to install all packages in requirements.txt onto created virtual environment while **disregarding** versions declared for packages in requirements.txt.
This increasing the chances and the probability that the automatic installation will succeed.

###### Usage
A New setting is introduced - `TRUSTIFY_DA_PYTHON_INSTALL_BEST_EFFORTS` (as both env variable/key in `options` object)
1. `TRUSTIFY_DA_PYTHON_INSTALL_BEST_EFFORTS`="false" - install requirements.txt while respecting declared versions for all packages.
2. `TRUSTIFY_DA_PYTHON_INSTALL_BEST_EFFORTS`="true" - install all packages from requirements.txt, not respecting the declared version, but trying to install a version tailored for the used python version. When using this setting, you must set setting `MATCH_MANIFEST_VERSIONS` to 'false'.

##### Using `pipdeptree`
By default, The API algorithm will use native commands of PIP installer as data source to build the dependency tree.
It's also possible to use the lightweight Python PIP utility [pipdeptree](https://pypi.org/project/pipdeptree/) as data source instead. In order to activate this, you need to set the environment variable/option `TRUSTIFY_DA_PIP_USE_DEP_TREE` to 'true'.

#### Toggle Red Hat Trusted Content recommendations
Both the HTML-based report and JSON response will by default contain recommendations for migrating to Red Hat-based Trusted Content repositories. This feature can be disabled by setting `TRUSTIFY_DA_RECOMMENDATIONS_ENABLED` to 'false' via environment variables or options.

#### Additional CLI arguments
For some ecosystems we support passing additional CLI arguments to the underlying tools. The following table outlines the supported ecosystems and the environment variable/option that configures this. Note that the arguments are expected to be in the format of a JSON array.

|Ecosystem|Key            |
|---------|---------------|
|Maven    |TRUSTIFY_DA_MVN_ARGS|


<!-- Badge links -->
[0]: https://img.shields.io/github/v/release/guacsec/trustify-da-javascript-client?color=green&label=latest
[1]: https://img.shields.io/github/v/release/guacsec/trustify-da-javascript-client?color=yellow&include_prereleases&label=early-access

### Known Issues

- For pip requirements.txt - It's been observed that for python versions 3.11.x, there might be slowness for invoking the analysis.
  If you encounter a performance issue with version >= 3.11.x, kindly try to set environment variable/option `TRUSTIFY_DA_PIP_USE_DEP_TREE=true`, before calling the analysis.


- For maven pom.xml, it has been noticed that using java 17 might cause stack analysis to hang forever.
  This is caused by maven [`dependency` plugin](https://maven.apache.org/plugins/maven-dependency-plugin/) bug when running with JDK/JRE' JVM version 17.

  To overcome this, you can use any other java version (14,20,21, etc..). ( best way is to install JDK/JRE version different from 17 , and set the location of the installation in environment variable `JAVA_HOME` so maven will use it.)
