# first stage
FROM registry.access.redhat.com/ubi9/nodejs-20 AS builder

# use privilaged user
USER root

# install Java
RUN curl -kL https://download.oracle.com/java/21/archive/jdk-21.0.1_linux-x64_bin.tar.gz -o /tmp/java-package.tar.gz \
    && tar xvzf /tmp/java-package.tar.gz -C /usr/

# install Maven package manager
RUN curl -kL https://archive.apache.org/dist/maven/maven-3/3.9.6/binaries/apache-maven-3.9.6-bin.tar.gz -o /tmp/maven-package.tar.gz \
    && tar xvzf /tmp/maven-package.tar.gz -C /usr/

# install golang package manager
RUN curl -kL https://go.dev/dl/go1.21.5.linux-amd64.tar.gz -o /tmp/golang-package.tar.gz \
    && tar xvzf /tmp/golang-package.tar.gz -C /usr/

# install jq JSON formating tool
RUN curl -kL https://github.com/jqlang/jq/releases/download/jq-1.8.1/jq-linux64 -o /usr/bin/jq

# Copy RHDA script (before changing WORKDIR)
COPY docker-image/scripts/rhda.sh /rhda.sh

# Copy project files and install Exhort javascript API locally
WORKDIR /app
COPY package.json package-lock.json ./
COPY dist ./dist
COPY config ./config
RUN npm install --production \
    && mkdir -p /app/node_modules/.bin \
    && ln -s /app/dist/src/cli.js /app/node_modules/.bin/trustify-da-javascript-client

# assign executable permissions to all installed binaries
RUN chmod +x /usr/jdk-21.0.1/bin/java \
    && chmod +x /usr/apache-maven-3.9.6/bin/mvn \
    && chmod +x /usr/go/bin/go \
    && chmod +x /usr/bin/jq \
    && chmod +x /app/dist/src/cli.js \
    && chmod +x /app/node_modules/.bin/trustify-da-javascript-client \
    && chmod +x /rhda.sh

# use default user
USER default

# second stage
FROM registry.access.redhat.com/ubi9/nodejs-20-minimal

# Build arguments for metadata
ARG IMAGE_VERSION
ARG IMAGE_REVISION
ARG IMAGE_CREATED

# Open Container Initiative (OCI) metadata labels
LABEL org.opencontainers.image.source=https://github.com/guacsec/trustify-da-javascript-client
LABEL org.opencontainers.image.description="Trustify Dependency Analytics JavaScript Client - Container image for dependency analysis and vulnerability scanning supporting Maven, NPM, Golang, and Python ecosystems"
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
# indicate whether to use the Minimal version selection (MVS) algorithm to select a set of module versions to use when building Go packages.
ENV TRUSTIFY_DA_GO_MVS_LOGIC_ENABLED='true'

# Copy java executable from the builder stage
COPY --from=builder /usr/jdk-21.0.1/ /usr/jdk-21.0.1/
ENV JAVA_HOME=/usr/jdk-21.0.1

# Copy maven executable from the builder stage
COPY --from=builder /usr/apache-maven-3.9.6/ /usr/apache-maven-3.9.6/
ENV MAVEN_HOME=/usr/apache-maven-3.9.6

# Copy golang executable from the builder stage
COPY --from=builder /usr/go/ /usr/go/
ENV GOLANG_HOME=/usr/go

# Update PATH
ENV PATH=$PATH:$JAVA_HOME/bin:$MAVEN_HOME/bin:$GOLANG_HOME/bin:/app/node_modules/.bin

# Copy jq executable from the builder stage
COPY --from=builder /usr/bin/jq /usr/bin/jq

# Copy trustify-da-javascript-client from the builder stage
COPY --from=builder /app /app

# Copy RHDA executable script from the builder stage
COPY --from=builder /rhda.sh /rhda.sh
