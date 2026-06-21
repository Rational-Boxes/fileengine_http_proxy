#!/bin/bash
# Script to generate gRPC files

PROTO_DIR="../proto"
PROTO_FILE="$PROTO_DIR/fileservice.proto"
OUTPUT_DIR="./proto/src"
INCLUDE_DIR="./proto/include"

mkdir -p $OUTPUT_DIR
mkdir -p $INCLUDE_DIR

protoc --plugin=protoc-gen-grpc=/usr/bin/grpc_cpp_plugin --grpc_out=$OUTPUT_DIR --cpp_out=$OUTPUT_DIR -I $PROTO_DIR $PROTO_FILE

# Copy header files to include directory
cp $OUTPUT_DIR/*.h $INCLUDE_DIR/