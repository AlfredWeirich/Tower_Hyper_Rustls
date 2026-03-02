#!/bin/bash
cargo run --bin grpc_server -p grpc_reflection -- -s https -u 192.168.178.175:50051 > grpc.log 2>&1 &
GRPC_PID=$!
sleep 2
cargo run --bin server -p server > proxy.log 2>&1 &
SERVER_PID=$!
sleep 5
kill $SERVER_PID
kill $GRPC_PID
