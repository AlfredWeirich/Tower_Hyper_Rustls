#!/bin/bash
cargo run --bin server -p server > proxy.log 2>&1 &
SERVER_PID=$!
sleep 5
# Fire 5 requests to /name. They should ALL be routed to 1338 because it returns score 100, while 1337 returns 50
for i in {1..5}; do
    curl -s -k https://192.168.178.175:1336/name >> curl.log
    echo "" >> curl.log
done
kill $SERVER_PID
