# Trustify Dependency Analytics Javascript Client Container Images

These dockerfiles provides all nessesary components to generate images for Trustify Dependency Analytics.
These images can be used as base images to set up the necessary environment and dependencies for running the Trustify Dependency Analytics.

## Prerequisites
Before getting started, ensure that you have one of the following prerequisites installed on your system:

- Docker: [Installation Guide](https://docs.docker.com/get-docker/)
- Podman: [Installation Guide](https://podman.io/docs/installation)

Both Docker and Podman are container runtimes that can be used to build and run the Trustify Dependency Analytics images. You can choose either Docker or Podman based on your preference and the compatibility with your operating system.

## Image generated for Trustify Dependency Analytics Javascript Client

ghcr.io/guacsec/trustify-da-javascript-client

See the [GitHub Container Registry](https://github.com/guacsec/trustify-da-javascript-client/pkgs/container/trustify-da-javascript-client)

Ecosystem                     | Version                                                            |
------------------------------| ------------------------------------------------------------------ | 
Maven | 3.9.12 |
Gradle | 9.2.1 |
Go | 1.25.5 |
NPM | 11.6.2 |
PNPM | 10.1.0 |
Yarn Classic | 4.9.1 |
Yarn Berry | 1.22.22 |
Python | 3.9.25 |

## Usage Notes

To perform RHDA analysis on a **Python** ecosystem, the data from both `pip freeze --all` and `pip show` commands should be generated for all packages listed in the requirements.txt manifest. This data should be encoded in base64 and passed through the `TRUSTIFY_DA_PIP_FREEZE` and `TRUSTIFY_DA_PIP_SHOW` environment variables, respectively.
Code example:
``` shell
# Install requirements.txt
pip3 install -r requirements.txt

# Generate pip freeze --all data
pip3 freeze --all > pip_freeze.txt

# Generate pip show data
SHOW_LIST=$(awk -F '==' '{print $1}' < pip_freeze.txt)
pip3 show $(echo "$SHOW_LIST") > pip_show.txt

# Encode data using base64 and export to environment variables
export TRUSTIFY_DA_PIP_FREEZE=$(cat pip_freeze.txt | base64 -w 0)
export TRUSTIFY_DA_PIP_SHOW=$(cat pip_show.txt | base64 -w 0)
```
