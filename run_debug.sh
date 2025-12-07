#!/bin/bash
echo "Starting debug run..." > debug_log.txt
./target/debug/rust_qt_netmon >> debug_log.txt 2>&1
EXIT_CODE=$?
echo "Exit code: $EXIT_CODE" >> debug_log.txt
