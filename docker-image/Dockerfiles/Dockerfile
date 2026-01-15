# first stage
FROM registry.access.redhat.com/ubi9/nodejs-24 AS builder

# use privileged user
USER root

# install OpenJDK from Adoptium (Eclipse Temurin) - latest JDK 21 LTS
RUN curl -kL "https://api.adoptium.net/v3/binary/latest/21/ga/linux/x64/jdk/hotspot/normal/eclipse" -o /tmp/java-package.tar.gz \
    && tar xvzf /tmp/java-package.tar.gz -C /usr/ \
    && mv /usr/jdk-21* /usr/temurin-21

# install Maven package manager
RUN curl -kL https://archive.apache.org/dist/maven/maven-3/3.9.12/binaries/apache-maven-3.9.12-bin.tar.gz -o /tmp/maven-package.tar.gz \
    && tar xvzf /tmp/maven-package.tar.gz -C /usr/

# install gradle package manager
RUN curl -kL https://services.gradle.org/distributions/gradle-9.2.1-bin.zip -o /tmp/gradle-package.zip \
    && unzip /tmp/gradle-package.zip -d /usr/

# install golang package manager
RUN curl -kL https://go.dev/dl/go1.25.5.linux-amd64.tar.gz -o /tmp/golang-package.tar.gz \
    && tar xvzf /tmp/golang-package.tar.gz -C /usr/

# install corepack and package managers (pnpm, yarn) - stage to /usr/local for easy copying
ENV COREPACK_HOME=/usr/local/corepack/cache
RUN npm install -g corepack@latest \
    && corepack enable \
    && corepack prepare pnpm@10.1.0 --activate \
    && corepack prepare yarn@4.9.1 --activate \
    && NPM_PREFIX=$(npm config get prefix) \
    && mkdir -p /usr/local/corepack/bin \
    && cp -rL $NPM_PREFIX/lib/node_modules/corepack/* /usr/local/corepack/ \
    && cp $NPM_PREFIX/bin/pnpm /usr/local/corepack/bin/ \
    && cp $NPM_PREFIX/bin/yarn /usr/local/corepack/bin/ \
    && cp $NPM_PREFIX/bin/yarnpkg /usr/local/corepack/bin/ \
    && cp $NPM_PREFIX/bin/corepack /usr/local/corepack/bin/ \
    && ln -s ../dist/lib /usr/local/corepack/bin/lib

# install jq JSON formating tool
RUN curl -kL https://github.com/jqlang/jq/releases/download/jq-1.8.1/jq-linux64 -o /usr/bin/jq

# Copy RHDA script (before changing WORKDIR)
COPY docker-image/scripts/trustify-da.sh /trustify-da.sh

# Copy project files and install Exhort javascript API locally
WORKDIR /app
COPY package.json package-lock.json ./
COPY dist ./dist
COPY config ./config
RUN npm install --production \
    && mkdir -p /app/node_modules/.bin \
    && ln -s /app/dist/src/cli.js /app/node_modules/.bin/trustify-da-javascript-client

# assign executable permissions to all installed binaries
RUN chmod +x /usr/temurin-21/bin/java \
    && chmod +x /usr/apache-maven-3.9.12/bin/mvn \
    && chmod +x /usr/gradle-9.2.1/bin/gradle \
    && chmod +x /usr/go/bin/go \
    && chmod +x /usr/bin/jq \
    && chmod +x /app/dist/src/cli.js \
    && chmod +x /app/node_modules/.bin/trustify-da-javascript-client \
    && chmod +x /trustify-da.sh

# use default user
USER default

# second stage
FROM registry.access.redhat.com/ubi9/nodejs-24-minimal

# Build arguments for metadata
ARG IMAGE_VERSION
ARG IMAGE_REVISION
ARG IMAGE_CREATED

# Open Container Initiative (OCI) metadata labels
LABEL org.opencontainers.image.source=https://github.com/guacsec/trustify-da-javascript-client
LABEL org.opencontainers.image.description="Trustify Dependency Analytics JavaScript Client - Container image for dependency analysis and vulnerability scanning supporting Maven, NPM, Golang, Gradle, Pnpm, Yarn, and Python ecosystems"
LABEL org.opencontainers.image.licenses=Apache-2.0
LABEL org.opencontainers.image.title="Trustify Dependency Analytics JavaScript Client"
LABEL org.opencontainers.image.vendor="guacsec"
LABEL org.opencontainers.image.url=https://github.com/guacsec/trustify-da-javascript-client
LABEL org.opencontainers.image.documentation=https://github.com/guacsec/trustify-da-javascript-client#README.md
LABEL org.opencontainers.image.version="${IMAGE_VERSION}"
LABEL org.opencontainers.image.revision="${IMAGE_REVISION}"
LABEL org.opencontainers.image.created="${IMAGE_CREATED}"

# contains pip feeze --all data, base64 encoded
ENV TRUSTIFY_DA_PIP_FREEZE=''
# contains pip show data for all packages, base64 encoded
ENV TRUSTIFY_DA_PIP_SHOW=''
# indicate whether to use the virtual environment for python packages
ENV TRUSTIFY_DA_PYTHON_VIRTUAL_ENV='true'

# Copy OpenJDK (Temurin) from the builder stage
COPY --from=builder /usr/temurin-21/ /usr/temurin-21/
ENV JAVA_HOME=/usr/temurin-21

# Copy maven executable from the builder stage
COPY --from=builder /usr/apache-maven-3.9.12/ /usr/apache-maven-3.9.12/
ENV MAVEN_HOME=/usr/apache-maven-3.9.12

# Copy golang executable from the builder stage
COPY --from=builder /usr/go/ /usr/go/
ENV GOLANG_HOME=/usr/go

# Copy gradle executable from the builder stage
COPY --from=builder /usr/gradle-9.2.1/ /usr/gradle-9.2.1/
ENV GRADLE_HOME=/usr/gradle-9.2.1

# Copy corepack and package manager binaries from builder stage
COPY --from=builder /usr/local/corepack/ /usr/local/corepack/
ENV COREPACK_HOME=/usr/local/corepack/cache

# Install Python via microdnf (cleanest approach for minimal images)
USER root
RUN microdnf install -y python3 python3-pip && microdnf clean all
USER 1001

# Update PATH (includes corepack bin for pnpm/yarn)
ENV PATH=$PATH:$JAVA_HOME/bin:$MAVEN_HOME/bin:$GOLANG_HOME/bin:$GRADLE_HOME/bin:/usr/local/corepack/bin:/app/node_modules/.bin

# Copy jq executable from the builder stage
COPY --from=builder /usr/bin/jq /usr/bin/jq

# Copy trustify-da-javascript-client from the builder stage
COPY --from=builder /app /app

# Copy trustify-da-javascript-client executable script from the builder stage
COPY --from=builder /trustify-da.sh /trustify-da.sh
