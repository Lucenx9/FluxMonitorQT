# Rust Qt Network Monitor

A network connection monitor built with Rust and Qt5.

## Building

If you have both Qt5 and Qt6 installed on your system, you need to force the build to use Qt5:

```bash
QMAKE=qmake-qt5 cargo build
```

Or use the provided helper script:
```bash
./build.sh
```

## Running

```bash
QMAKE=qmake-qt5 cargo run
```

Or use the provided helper script:
```bash
./run.sh
```

## Qt5/Qt6 Conflict

The `qttypes` crate (dependency of `qmetaobject`) tries to auto-detect Qt by checking for `qmake6`, `qmake`, and `qmake-qt5` in that order. If both Qt5 and Qt6 are installed and `qmake6` exists, it will use Qt6 by default, causing library conflicts with this Qt5-based application.

The solution is to set the `QMAKE` environment variable to explicitly use `qmake-qt5` before building.

## Requirements

- Rust
- Qt5 development libraries
- A display environment (DISPLAY or WAYLAND_DISPLAY)
