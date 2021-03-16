#!/bin/bash

DOCKER_TAG="packmad:siggregator"  # docker build . -t packmad:siggregator
TARGET="${@: -1}"  # last argument is target file
INPUT_DIR=$(cd $(dirname "$TARGET") && pwd -P)
INPUT_FILE=$(basename $TARGET)

if [ "$#" -eq 1 ]; then
  docker run --rm --volume "$INPUT_DIR":/input:ro -i $DOCKER_TAG "/input/$INPUT_FILE";
else
  echo "Missing argument!"
fi