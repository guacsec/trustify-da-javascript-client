# first stage
FROM registry.access.redhat.com/ubi9/nodejs-20 AS builder

# use privilaged user
USER root

ARG TRUSTIFY_DA_JAVASCRIPT_API_VERSION='0.2.4-ea.12'

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
RUN curl -kL https://github.com/jqlang/jq/releases/download/jq-1.7.1/jq-linux64 -o /usr/bin/jq

# install Exhort javascript API
RUN npm install --global @trustify-da/trustify-da-javascript-client@${TRUSTIFY_DA_JAVASCRIPT_API_VERSION}

# add RHDA script
COPY scripts/rhda.sh /rhda.sh

# assign executable permissions to all installed binaries
RUN chmod +x /usr/jdk-21.0.1/bin/java \
    && chmod +x /usr/apache-maven-3.9.6/bin/mvn \
    && chmod +x /usr/go/bin/go \
    && chmod +x /usr/bin/jq \
    && chmod +x /opt/app-root/src/.npm-global/bin/trustify-da-javascript-client \
    && chmod +x /rhda.sh

# use default user
USER default

# second stage
FROM registry.access.redhat.com/ubi9/nodejs-20-minimal

LABEL org.opencontainers.image.source=https://github.com/guacsec/trustify-da-javascript-client

# assign rhda source for exhort tracking purposes
ENV RHDA_SOURCE=''
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
ENV PATH=$PATH:$JAVA_HOME/bin:$MAVEN_HOME/bin:$GOLANG_HOME/bin

# Copy jq executable from the builder stage
COPY --from=builder /usr/bin/jq /usr/bin/jq

# Copy trustify-da-javascript-client executable from the builder stage
COPY --from=builder /opt/app-root/src/.npm-global/ /opt/app-root/src/.npm-global/

# Copy RHDA executable script from the builder stage
COPY --from=builder /rhda.sh /rhda.sh
