#!/bin/bash
# Run script that forces Qt5 when both Qt5 and Qt6 are installed
QMAKE=qmake-qt5 cargo run "$@"
