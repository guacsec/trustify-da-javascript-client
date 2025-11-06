#!/usr/bin/env bash

#!!!!! DO NOT FORGET 'npm run compile' on root prior to running this script !!!!#

# set TRUSTIFY_DA_ITS_USE_REAL_API=true to use the real backend
TRUSTIFY_DA_ITS_USE_REAL_API="${TRUSTIFY_DA_ITS_USE_REAL_API:=false}"

# utility function for wrapping up and exiting
# takes an exit code
cleanup() {
	# PID is set when we start the mock server
	if [ -n "${PID}" ]; then
		echo "STOPPING Mock HTTP Server"
		if ! kill "$PID"; then
			echo "- FAILED Killing PID $PID"
		else
			echo "- SUCCESSFUL"
		fi
	fi
	exit "$1"
}

matchConstant() {
    TEST_MESSAGE="$3"
    sleep 1
    echo "$TEST_MESSAGE"
    if [[ "$1" != "$2" ]]; then
		echo "- FAILED"
		echo "expected = $1, actual= $2"
		cleanup 1
    fi
    echo "- PASSED"
    echo
}

##########################################
###### Verify Required Tools Exists ######
##########################################
echo "VERIFYING Node and NPM availability"
if ! node --version > /dev/null 2>&1; then
	RC="$?"
	echo "- FAILED Node not found"
	cleanup $RC
fi

if ! npm --version > /dev/null 2>&1; then
	RC="$?"
	echo "- FAILED NPM not found"
	cleanup $RC
fi
echo "- SUCCESSFUL"

echo "VERIFYING Java and Maven availability"
if ! java --version > /dev/null 2>&1; then
	RC="$?"
	echo "- FAILED Java not found"
	cleanup $RC
fi

if ! mvn --version > /dev/null 2>&1; then
	RC="$?"
	echo "- FAILED Maven not found"
	cleanup $RC
fi
echo "- SUCCESSFUL"


##########################################
###### Preparing CLI Tests ######
##########################################
echo "PREPARING JavaScript CLI tests environment"
rm -rf testers/cli/node_modules
rm -f testers/cli/package-lock.json
if !  npm --prefix testers/cli install  --silent ; then
	RC="$?"
	echo "- FAILED Installing trustify-da-javascript-client environment for testing"
	cleanup $RC
fi
echo "- SUCCESSFUL"
mkdir -p ./responses
#### JAVA MAVEN
echo "RUNNING JavaScript CLI integration test for Stack Analysis report in Html for Java Maven"

testers/cli/node_modules/.bin/trustify-da-javascript-client  stack scenarios/maven/pom.xml --html > ./responses/stack.html
RC="$?"
if [ "$RC" -ne 0 ]; then
	echo "- FAILED, return $RC from invocation"
	cleanup $RC
fi
RESPONSE_CONTENT=$(grep -i "DOCTYPE html" ./responses/stack.html)
if [[ -z "${RESPONSE_CONTENT}"  ]]; then
    echo "- FAILED, response is not valid html: $RESPONSE_CONTENT"
	cleanup 1
fi
echo "- PASSED"
echo

echo 'RUNNING JavaScript CLI integration test for Stack Analysis report summary of snyk provider for Java Maven'
testers/cli/node_modules/.bin/trustify-da-javascript-client stack scenarios/maven/pom.xml --summary > ./responses/stack-summary.json
RC="$?"
if [ "$RC" -ne 0 ]; then
	echo "- FAILED, return $RC from invocation"
	cleanup $RC
fi

if ! RESPONSE_CONTENT=$(jq . ./responses/stack-summary.json); then
	RC="$?"
	echo "- FAILED, response is not a valid json: $RESPONSE_CONTENT"
	cleanup $RC
fi
echo
echo "$RESPONSE_CONTENT"
echo "- PASSED"
echo

echo "RUNNING JavaScript CLI integration test for Stack Analysis report in Json for Java Maven"
testers/cli/node_modules/.bin/trustify-da-javascript-client stack scenarios/maven/pom.xml  > ./responses/stack.json
RC="$?"
if [ "$RC" -ne 0 ]; then
	echo "- FAILED, return $RC from invocation"
	cleanup $RC
fi

if ! RESPONSE_CONTENT=$(jq . ./responses/stack.json); then
	RC="$?"
	echo "- FAILED, response is not a valid json: $RESPONSE_CONTENT"
	cleanup $RC
fi

StatusCodeTC=$(jq '.providers["trusted-content"].status.code' ./responses/stack.json)
matchConstant "200" "$StatusCodeTC" "Check that Response code from Trusted Content is OK ( Http Status = 200)..."

#StatusCodeSnyk=$(jq '.providers.snyk.status.code' ./responses/stack.json)
#matchConstant "200" "$StatusCodeSnyk" "Check that Response code from Snyk Provider is OK ( Http Status = 200)..."

echo "RUNNING JavaScript CLI integration test for Component Analysis report for Java Maven"
eval "testers/cli/node_modules/.bin/trustify-da-javascript-client component scenarios/maven/pom.xml"  > ./responses/component.json
RC="$?"
if [ "$RC" -ne 0 ]; then
	echo "- FAILED, return $RC from invocation"
	cleanup $RC
fi

if ! RESPONSE_CONTENT=$(jq . ./responses/component.json); then
	RC="$?"
	echo "- FAILED, response is not a valid json, got $RC from parsing the file"
	cleanup $RC
fi

StatusCodeTC=$(jq '.providers["trusted-content"].status.code' ./responses/stack.json)
matchConstant "200" "$StatusCodeTC" "Check that Response code from Trusted Content is OK ( Http Status = 200)..."

cleanup 0
