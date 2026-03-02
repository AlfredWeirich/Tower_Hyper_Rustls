#!/bin/bash
cargo run --bin server -p server > proxy.log 2>&1 &
SERVER_PID=$!
sleep 5
curl -k -v https://192.168.178.175:1337/health > curl.log 2>&1
kill $SERVER_PID
