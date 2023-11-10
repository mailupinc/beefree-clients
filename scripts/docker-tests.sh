#!/bin/bash
set -u # or set -o nounset
SCRIPT_NAME=$( basename $0 )
SCRIPT_DIR="$( cd "$( dirname "$0" )" && pwd )"
PRJ_DIR="$( cd "${SCRIPT_DIR}/.." && pwd )"
PRJ_NAME=$( basename ${PRJ_DIR} )


###################################################################################################
# Simulate the jenkis pipeline 
# - running tests form test.Dockerfile 
# - extracting results in a local dir
#

export bee_env=test
export build_target=test
export COMPOSE_DOCKER_CLI_BUILD=1
export DOCKER_BUILDKIT=1
export COMPOSE_PROJECT_NAME=beepro-clients
export git_sha=$(git rev-parse --short --verify HEAD  2> /dev/null  )
export git_tag="${git_sha}-tests"
export USER_ID=$(id -u)
export GROUP_ID=$(id -g)

prj_tag="$(whoami)/${PRJ_NAME}"
prj_tag_version="${git_sha}-local"
name_tag="${prj_tag}-test:${prj_tag_version}"

cat << EOF
    SCRIPT_NAME: ${SCRIPT_NAME}
    PRJ_DIR    : ${PRJ_DIR}
    PRJ_NAME   : ${PRJ_NAME}
EOF

docker-compose -f docker/docker-compose-test.yml build
docker-compose -f docker/docker-compose-test.yml run --rm beefree-clients
docker-compose -f docker/docker-compose-test.yml down

echo "<>--<>--<>--<>--<>--<>"
echo "Dir with test results"
echo "<>--<>--<>--<>--<>--<>"
echo "Files to view "
find "${PRJ_DIR}/tests_reports" -iname index.html -o -iname report.html -o -iname junit.xml
echo ""
