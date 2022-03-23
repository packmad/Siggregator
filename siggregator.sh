#!/bin/bash

DOCKER_TAG="packmad:siggregator"  # docker build . -t packmad:siggregator

if [ "$#" -eq 2 ] && [[ -d $1 ]]; then

  TARGET="$2"  # second argument is OUT_FILE
  OUT_DIR=$(cd $(dirname "$TARGET") && pwd -P)
  OUT_FILE_NAME=$(basename "$TARGET")

  docker run --rm --volume "$1":/input:ro --volume "$OUT_DIR":/output -i $DOCKER_TAG "--csv" "--hashes" "--dir" "/input/" "--out" "/output/$OUT_FILE_NAME";
else
  echo "Usage: siggregator.sh IN_DIR OUT_FILE"
fi