#!/bin/bash

OUT_DIR="out"

APP="honey"
SRC="."

if [ ! -d ${OUT_DIR} ]; then
	mkdir ${OUT_DIR}
fi

out=${OUT_DIR}/${APP}

go build -o ${out} ${SRC}

echo "OK, output been located at: ${out}"
